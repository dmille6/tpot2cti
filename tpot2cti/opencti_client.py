"""tpot2cti — pycti client wrapper.

Thin wrapper around ``pycti.OpenCTIApiClient`` that defends against the
specific footguns the predecessor platform hit and documented in
``docs/LESSONS_LEARNED_FROM_V0.md``:

* **§8.1** — ``OpenCTIApiClient.__init__`` (and the connector-helper
  variant) calls :func:`logging.basicConfig` and clobbers root-logger
  handlers. We call :func:`tpot2cti.log.setup_logging` first, then
  :func:`tpot2cti.log.restore_logging` immediately after, so JSON logs
  keep flowing.
* **§8.2** — empty ``CONNECTOR_ID`` makes pycti error asynchronously
  with a ``BAD_USER_INPUT`` GraphQL error that looks like a transient
  network blip but is actually fatal. We validate up front and raise
  :class:`ConfigError`.
* **§8.4** — pycti silently drops bundles containing unknown STIX types.
  We don't fix that here — see :mod:`tpot2cti.stix.types` and
  :mod:`tpot2cti.publisher` for the allowlist check that runs before
  each bundle goes out — but the cross-reference is in the docstrings
  so future readers find it.

Per V1_SPEC §3 ("Sync-only HTTP", lines 295-299) we use the synchronous
pycti API only. Never aiohttp / asyncio from within pycti's RabbitMQ
callback threads.

Per V1_SPEC §3 lines 278-294, the three-pass send orchestration lives
in :mod:`tpot2cti.publisher`. This module's job is to talk to pycti
safely and report what happened; the publisher decides what to send
and when.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

from tpot2cti.config import ConfigError, OpenCTIConfig
from tpot2cti import log as tpot2cti_log

logger = logging.getLogger(__name__)


# Captured at import time when pycti is available. Logged on first
# instantiation. ``None`` when pycti is not installed (smoke tests can
# still exercise the wrapper via dependency injection).
PYCTI_VERSION: Optional[str] = None
try:  # pragma: no cover - import-time best effort
    import pycti as _pycti  # type: ignore

    PYCTI_VERSION = getattr(_pycti, "__version__", "unknown")
except Exception:  # noqa: BLE001 - pycti may legitimately be absent in tests
    _pycti = None  # type: ignore


class OpenCTIClient:
    """Synchronous wrapper around :class:`pycti.OpenCTIApiClient`.

    Args:
        cfg: Parsed :class:`OpenCTIConfig` (URL + admin token).
        connector_id: UUID string identifying this connector to OpenCTI.
            Sourced from ``Config.connector_ids.core`` by the caller.
            Cannot be empty / whitespace (see LESSONS §8.2).
        client_factory: Optional callable used to construct the
            underlying pycti client. Defaults to
            :class:`pycti.OpenCTIApiClient`. Provided for tests that
            cannot reach a live OpenCTI; production callers should
            leave this ``None``.

    Raises:
        ConfigError: If ``connector_id`` is empty / whitespace.
    """

    def __init__(
        self,
        cfg: OpenCTIConfig,
        connector_id: str,
        client_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        # --- LESSONS §8.2 — empty CONNECTOR_ID footgun ---------------------
        if not connector_id or not str(connector_id).strip():
            raise ConfigError(
                "OpenCTI connector_id is empty or whitespace. pycti accepts "
                "this and then fails asynchronously with BAD_USER_INPUT "
                "after the first cycle, which looks like a transient network "
                "error but is fatal. See "
                "docs/LESSONS_LEARNED_FROM_V0.md §8.2."
            )

        self.cfg = cfg
        self.connector_id = connector_id

        # --- LESSONS §8.1 — handler hijack defense -------------------------
        # main.py / selftest.py is expected to have called setup_logging()
        # already; we only need restore_logging() AFTER pycti runs to
        # rebuild the file handler.  We deliberately do NOT re-call
        # setup_logging() here — per 2026-05-22 audit L1 follow-on, a
        # zero-arg setup_logging() call wiped the file_handler config
        # main.py had set, silently breaking durable file logs for the
        # entire process lifetime.  setup_logging() is now self-defending
        # against that footgun (preserves cached file config on a no-arg
        # call), but the cleanest fix is to not call it twice.
        factory = client_factory or _default_client_factory()
        logger.info(
            f"Instantiating OpenCTIApiClient: url={cfg.url} "
            f"connector_id={connector_id} pycti_version={PYCTI_VERSION}"
        )
        self._api = factory(
            url=cfg.url,
            token=cfg.admin_token,
        )

        # --- LESSONS §8.1 — restore our handlers after pycti clobbers them.
        tpot2cti_log.restore_logging()

        logger.info("OpenCTIApiClient ready.")

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def send_bundle(
        self, bundle: dict, update: bool = False
    ) -> dict[str, Any]:
        """Send one STIX bundle dict to OpenCTI.

        ``bundle`` should be a full STIX bundle envelope::

            {"type": "bundle", "id": "bundle--<uuid>", "objects": [...]}

        We delegate to ``pycti.stix2.import_bundle_from_json``. pycti
        accepts a JSON string; we serialize here so callers pass dicts
        (which is what the publisher has on hand after dedup).

        Returns:
            ``{"sent": N, "duration_s": <float>, "raw_response": ...}``.
            On exception, logs WARNING with the LESSONS cross-references
            and re-raises so the publisher can decide whether to abort
            the cycle or continue to the next pass.
        """
        import json as _json

        objects = bundle.get("objects") or []
        n = len(objects)
        started = time.monotonic()
        try:
            raw = self._api.stix2.import_bundle_from_json(
                _json.dumps(bundle), update=update
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"OpenCTI import_bundle_from_json raised {type(exc).__name__}: "
                f"{exc}. Cross-refs: LESSONS §8.2 (auth/connector-id), "
                f"§8.3 (mutation endpoint mismatch), §8.4 (silent type drop). "
                f"Bundle had {n} object(s)."
            )
            raise
        duration_s = time.monotonic() - started
        logger.info(
            f"Bundle sent: {n} object(s), duration={duration_s:.2f}s"
        )
        return {
            "sent": n,
            "duration_s": duration_s,
            "raw_response": raw,
        }

    def health_check(self) -> bool:
        """Cheap GraphQL ping used by the Phase 6 /health endpoint.

        Tries ``self._api.health()`` first (newer pycti versions), then
        falls back to a benign ``query`` call. Returns ``False`` on any
        exception — health is best-effort and never raises.
        """
        try:
            health = getattr(self._api, "health", None)
            if callable(health):
                result = health()
                return bool(result) if result is not None else True
            # Fallback: any pycti query proves the GraphQL endpoint is up.
            self._api.query("query { about { version } }")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"OpenCTI health_check failed: {type(exc).__name__}: {exc}"
            )
            return False


def _default_client_factory() -> Callable[..., Any]:
    """Return the real pycti API client constructor.

    Deferred so importing this module doesn't hard-fail when pycti is
    missing (tests use a stub factory; pycti is only needed in
    production).
    """
    if _pycti is None:
        raise ConfigError(
            "pycti is not installed. Add `pycti>=6.4,<8` to requirements.txt "
            "and rebuild the container. See V1_SPEC §3."
        )
    return _pycti.OpenCTIApiClient  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg = OpenCTIConfig(url="http://localhost:8080", admin_token="dummy")

    # --- Case 1: empty connector_id must raise ConfigError ----------------
    for bad in ("", "   ", None):
        try:
            OpenCTIClient(cfg, connector_id=bad)  # type: ignore[arg-type]
        except ConfigError as e:
            assert "LESSONS_LEARNED_FROM_V0.md §8.2" in str(e), (
                "ConfigError should cross-reference LESSONS §8.2"
            )
        else:
            print(
                f"FAIL: empty connector_id {bad!r} did not raise ConfigError",
                file=sys.stderr,
            )
            sys.exit(1)

    # --- Case 2: with a stub factory, instantiation succeeds --------------
    class _StubApi:
        def __init__(self, url: str, token: str) -> None:
            self.url = url
            self.token = token
            self.stix2 = self  # so .stix2.import_bundle_from_json resolves

        def import_bundle_from_json(self, payload, update=False):
            return {"stub": True, "len": len(payload)}

        def health(self) -> bool:
            return True

    def _stub_factory(url: str, token: str) -> _StubApi:
        return _StubApi(url, token)

    client = OpenCTIClient(
        cfg, connector_id="11111111-2222-3333-4444-555555555555",
        client_factory=_stub_factory,
    )
    assert client.health_check() is True, "health_check should pass on stub"

    stats = client.send_bundle(
        {"type": "bundle", "id": "bundle--x", "objects": [{"type": "identity"}]}
    )
    assert stats["sent"] == 1, f"expected sent=1, got {stats!r}"
    assert stats["duration_s"] >= 0

    # --- Case 3: send_bundle should re-raise and log on exception ---------
    class _BrokenApi(_StubApi):
        def import_bundle_from_json(self, payload, update=False):
            raise RuntimeError("simulated GraphQL failure")

    broken = OpenCTIClient(
        cfg, connector_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        client_factory=lambda url, token: _BrokenApi(url, token),
    )
    try:
        broken.send_bundle({"type": "bundle", "id": "bundle--y", "objects": []})
    except RuntimeError:
        pass
    else:
        print("FAIL: broken stub should have re-raised", file=sys.stderr)
        sys.exit(1)

    print("OK")
