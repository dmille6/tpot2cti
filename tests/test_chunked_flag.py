"""The chunked-publish flag must default OFF and fail to serial, not silently.

v2 publishes at 1.04x the throughput it needs -- break-even with no margin --
because the serial path issues one GraphQL mutation per object and waits on
each. Measured on live v2 infrastructure, the chunked queue path did 15.7
obj/s against the 5.5 obj/s serial baseline (2.9x).

Two failure modes this guards, both of which nearly shipped:

  * the helper is built unconditionally -- pycti resets the root logger and
    the connector registers itself, side effects nobody asked for when the
    feature is off;
  * a broken helper falls back to serial SILENTLY, leaving throughput
    unchanged with no indication the flag did nothing. The import path was
    wrong on the first attempt (`tpot2cti.logging_setup` instead of
    `tpot2cti.log`) and that is exactly what would have happened.
"""
import os
import re

MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "tpot2cti", "main.py")
PUB = os.path.join(os.path.dirname(MAIN), "publisher.py")


def test_flag_defaults_off():
    src = open(MAIN).read()
    m = re.search(r'"TPOT2CTI_CHUNKED_PUBLISH",\s*"([^"]+)"', src)
    assert m, "the flag must be read from the environment with an explicit default"
    assert m.group(1).lower() == "false", (
        f"default is {m.group(1)!r}; a transport change must be opt-in"
    )


def test_helper_is_only_built_when_the_flag_is_on():
    src = open(MAIN).read()
    i = src.index("_pub_helper = None")
    block = src[i:i + 1200]
    assert "if _chunked:" in block, (
        "OpenCTIConnectorHelper must not be constructed unless the flag is "
        "set — it hijacks the root logger and registers the connector"
    )
    assert block.index("if _chunked:") < block.index("OpenCTIConnectorHelper")


def test_a_broken_helper_falls_back_LOUDLY():
    src = open(MAIN).read()
    i = src.index("_pub_helper = None")
    block = src[i:i + 1800]
    assert "logger.error" in block, (
        "a failure to build the helper must log at ERROR — a silent fallback "
        "leaves throughput unchanged with nothing saying the flag did nothing"
    )
    assert "FALLING BACK TO SERIAL" in block


def test_restore_logging_is_imported_from_the_module_that_has_it():
    """The first attempt imported from a module that does not exist.

    It would have raised, hit the fallback, and run serial for ever while the
    flag read as enabled.
    """
    src = open(MAIN).read()
    assert "from tpot2cti.log import restore_logging" in src
    assert "logging_setup" not in src
    log_src = open(os.path.join(os.path.dirname(MAIN), "log.py")).read()
    assert "def restore_logging" in log_src


def test_publisher_uses_serial_when_no_helper_is_given():
    src = open(PUB).read()
    assert "if self.helper is not None:" in src
    i = src.index("if self.helper is not None:")
    assert "self.client.send_bundle(envelope)" in src[i:i + 2000], (
        "the else branch must still be the serial path"
    )


def test_an_unclean_chunked_pass_does_not_raise_but_is_recorded():
    """Raising would discard passes that DID land.

    Re-covering a window is free -- deterministic ids, max(score) merge --
    while skipping one is undetectable. So an unclean pass appends an error
    and lets publish_is_clean() refuse the cursor.
    """
    src = open(PUB).read()
    i = src.index("chunked pass not clean")
    ctx = src[i - 600:i + 300]
    assert "errors.append" in ctx
    assert "raise" not in ctx.split("chunked pass not clean")[0][-300:]


def test_the_transport_is_recorded_so_the_ab_is_a_query():
    src = open(PUB).read()
    assert 'transport="chunked" if self.helper is not None else "serial"' in src, (
        "publish_pass rows must say which transport produced them, or the "
        "before/after comparison is a memory rather than a query"
    )
