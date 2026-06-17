"""Standalone tests for the vault OpenCTI publisher (run: python -m pytest tpot2cti-vault)."""
import opencti


class _Cfg:
    publish_to_opencti = False
    sensor_name = "test"
    opencti_url = "http://x"
    opencti_token = "t"


def test_publish_noop_when_disabled(tmp_path):
    p = tmp_path / "sample"
    p.write_bytes(b"malware-bytes")
    # disabled -> returns False, performs no network call
    assert opencti.publish_stixfile(_Cfg(), "a" * 64, str(p), "dionaea", 13) is False


def test_md5_sha1_helper(tmp_path):
    p = tmp_path / "s"
    p.write_bytes(b"abc")
    md5, sha1 = opencti._md5_sha1(str(p))
    assert md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert sha1 == "a9993e364706816aba3e25717850c26c9cd0d89d"
