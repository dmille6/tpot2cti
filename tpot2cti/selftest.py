"""tpot2cti — install self-test.

Run inside the tpot2cti-core container after `docker compose up -d`
completes to verify the end-to-end emit path before the first scheduled
cycle. Catches pycti version drift / OpenCTI API breakage at install
time rather than during the first cycle when an operator has to debug
in production.

What it does:
  1. Load config (from env / .env).
  2. Instantiate the OpenCTIClient (verifies pycti import + connector_id
     guard + logger restore).
  3. Call the platform health endpoint via pycti's `about()`.
  4. Construct a minimal foundation bundle (the operator Identity +
     TLP marking) — both idempotent UUID5s, so re-running this self-test
     is a no-op upsert on OpenCTI's side.
  5. Send the bundle via Publisher; require no errors.

Usage (from inside the container):
    python3 -m tpot2cti.selftest

Usage (from the host, via docker exec):
    docker exec tpot2cti-core python3 -m tpot2cti.selftest

Exits 0 on success, non-zero on any failure with a clear diagnostic.
"""

from __future__ import annotations

import logging
import sys

from tpot2cti.config import load_config
from tpot2cti.log import setup_logging, restore_logging
from tpot2cti.opencti_client import OpenCTIClient
from tpot2cti.publisher import Publisher
from tpot2cti.stix.builder import STIXBuilder


def main() -> int:
    cfg = load_config()
    setup_logging(cfg.logging)
    logger = logging.getLogger("tpot2cti.selftest")

    logger.info("=== tpot2cti install self-test ===")
    logger.info(
        f"operator={cfg.operator.org_name!r} tlp={cfg.operator.default_tlp} "
        f"opencti={cfg.opencti.url}"
    )

    # 1) pycti instantiation + connector_id guard + logger restore
    try:
        client = OpenCTIClient(cfg.opencti, connector_id=cfg.connector_ids.core)
        restore_logging()
        logger.info("OK: pycti OpenCTIApiClient instantiated")
    except Exception as e:
        logger.error(f"FAIL: OpenCTIClient instantiation: {e}")
        return 2

    # 2) Health check via pycti
    try:
        healthy = client.health_check()
        if not healthy:
            logger.error("FAIL: client.health_check() returned False")
            return 3
        logger.info("OK: OpenCTI platform health check passed")
    except Exception as e:
        logger.error(f"FAIL: health_check raised: {e}")
        return 3

    # 3) Build a minimal foundation bundle.
    builder = STIXBuilder(cfg)
    objects = [
        builder.build_operator_identity(),
        builder.build_tlp_marking(),
    ]
    objects = [o for o in objects if o is not None]
    if len(objects) != 2:
        logger.error(
            f"FAIL: builder produced {len(objects)} objects; expected 2 "
            f"(operator identity + TLP marking). "
            f"Check STIXBuilder construction."
        )
        return 4
    logger.info(f"OK: built {len(objects)} foundation STIX objects")

    # 4) Publish — should ship via three-pass (only foundation pass non-empty).
    publisher = Publisher(
        client,
        state=None,  # no state DB write for the self-test
        indexing_delay_seconds=0,  # skip the inter-pass sleeps for speed
    )
    try:
        result = publisher.publish(objects, cycle_id="selftest")
    except Exception as e:
        logger.error(f"FAIL: publisher.publish raised: {e}")
        return 5

    if result.errors:
        logger.error(
            f"FAIL: publish completed with {len(result.errors)} error(s): "
            f"{result.errors}"
        )
        return 5

    logger.info(
        f"OK: published bundle in {result.duration_s:.2f}s — "
        f"foundation={result.pass_counts.get('foundation', 0)} "
        f"entities={result.pass_counts.get('entities', 0)} "
        f"relationships={result.pass_counts.get('relationships', 0)}"
    )

    logger.info("=== self-test passed — first real cycle should succeed ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
