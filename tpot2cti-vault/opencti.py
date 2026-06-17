"""Publish vault malware samples to OpenCTI as StixFile observables.

The vault fetches + stages malware bytes; this turns each NEW sample into a
hash-keyed StixFile IOC (SHA-256/MD5/SHA-1 + size) so analysts get shareable
indicators, not just files on disk. Best-effort: failures are logged and never
break the fetch cycle. The raw bytes are NOT uploaded -- they stay in the vault.
"""
from __future__ import annotations

import hashlib
import json
import logging
import urllib.request

logger = logging.getLogger("tpot2cti.vault.opencti")

_ADD_STIXFILE = (
    "mutation($sha256:String!,$md5:String!,$sha1:String!,$size:Int!,$desc:String!){"
    " stixCyberObservableAdd(type:\"StixFile\",x_opencti_score:90,x_opencti_description:$desc,"
    "StixFile:{hashes:["
    "{algorithm:\"SHA-256\",hash:$sha256},"
    "{algorithm:\"MD5\",hash:$md5},"
    "{algorithm:\"SHA-1\",hash:$sha1}"
    "],name:$sha256,size:$size}){id} }"
)


def _md5_sha1(path: str) -> tuple[str, str]:
    md5, sha1 = hashlib.md5(), hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
    return md5.hexdigest(), sha1.hexdigest()


def publish_stixfile(cfg, sha256: str, sample_path: str, honeypot: str, size: int) -> bool:
    """Create a StixFile observable for one captured sample. No-op (returns
    False) when OpenCTI isn't configured. Never raises -- the fetch cycle must
    survive a flaky OpenCTI."""
    if not getattr(cfg, "publish_to_opencti", False):
        return False
    try:
        md5, sha1 = _md5_sha1(sample_path)
        desc = (
            "Malware sample captured by %s on T-Pot sensor %r. %d bytes. "
            "Raw bytes retained in the tpot2cti malware-vault." % (honeypot, cfg.sensor_name, size)
        )
        body = json.dumps({"query": _ADD_STIXFILE, "variables": {
            "sha256": sha256, "md5": md5, "sha1": sha1, "size": int(size), "desc": desc,
        }}).encode()
        req = urllib.request.Request(
            cfg.opencti_url.rstrip("/") + "/graphql", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + cfg.opencti_token})
        resp = json.load(urllib.request.urlopen(req, timeout=30))
        if resp.get("errors"):
            logger.warning("vault: OpenCTI StixFile publish error for %s: %s",
                           sha256[:16], str(resp["errors"])[:160])
            return False
        logger.info("vault: published StixFile IOC sha256=%s", sha256)
        return True
    except Exception as exc:  # noqa: BLE001 -- best-effort, never break the cycle
        logger.warning("vault: OpenCTI StixFile publish failed for %s: %s", sha256[:16], exc)
        return False
