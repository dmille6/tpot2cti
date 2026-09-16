"""The fetch/parse phase must report FORWARD PROGRESS, not elapsed time.

The cycle used to print nothing between starting an ES stream and finishing
the build: one run was silent from 12:12 to 13:05 while RSS climbed 1.4 ->
13 GiB. A stall in that window was indistinguishable from normal work.

The distinction these tests defend is why a heartbeat exists at all. This
project's recurring injury is a reassuring signal decoupled from real work
-- a green systemd timer that never ran a successful job, an ES zero read as
"fine" because the field name was wrong, every component self-reporting
healthy while ~9,000 attackers fell between two of them. "still working,
1800s elapsed" is that same lie repainted: a wedged socket emits it just as
faithfully as a busy one.

So: the tick must carry a DELTA, a zero delta must be loud, and the thread
must die with the phase it describes.
"""
from __future__ import annotations

import os
import re

MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "tpot2cti", "main.py")


def _src() -> str:
    return open(MAIN).read()


def test_heartbeat_reports_a_delta_not_only_elapsed_time():
    src = _src()
    i = src.index("def _fetch_parse_heartbeat")
    body = src[i:i + 2200]
    assert "delta = cur - prev" in body, (
        "the tick must compute progress since the previous tick; an elapsed-"
        "time counter alone cannot distinguish slow from stopped"
    )
    assert "+%d in 30s" in body or "+%d" in body, (
        "the delta must appear in the log line, not just be computed"
    )


def test_zero_progress_is_logged_above_info():
    """A stall must not be reported at the same level as healthy work."""
    src = _src()
    i = src.index("def _fetch_parse_heartbeat")
    body = src[i:i + 2200]
    assert "if delta == 0:" in body
    assert re.search(r"logger\.error if stalled >= \d+ else logger\.warning", body), (
        "zero forward progress must log at WARNING and escalate to ERROR — "
        "at INFO it is indistinguishable from the healthy tick"
    )


def test_heartbeat_is_stopped_on_every_exit_path():
    """Left running, it would describe fetch/parse during the publish phase.

    A liveness signal that keeps reporting work which already finished is
    precisely the failure the heartbeat was added to prevent.
    """
    src = _src()
    start = src.index("_hb = threading.Thread(target=_fetch_parse_heartbeat")
    stop = src.index("_hb_stop.set()", start)
    between = src[start:stop]
    assert "finally:" in between, (
        "the heartbeat thread must be stopped in a finally, not only on the "
        "success path — an exception mid-stream would leave it printing"
    )
    # and the finally must be the LAST block before the stop, not an
    # unrelated one earlier in the loop
    assert between.rindex("finally:") > between.rindex("except "), (
        "_hb_stop.set() is not inside the finally that guards the loop"
    )


def test_counters_are_fed_from_inside_the_loop():
    """Sampled from the real loop counter, not a wrapper that assumes progress."""
    src = _src()
    assert re.search(r"if events_read % \d+ == 0:", src), (
        "progress must be sampled from inside the fetch/parse loop"
    )
    i = src.index("if events_read % ")
    assert '_hb_progress["read"] = events_read' in src[i:i + 400]


def test_a_semantic_invariant_guards_progress_on_the_wrong_data():
    """The residual lie a progress heartbeat cannot catch.

    If the ES query matches the wrong population — a renamed field, a changed
    mapping — every counter climbs honestly and fast while the result is
    entirely wrong. Throughput is blind to correctness, so the cycle also has
    to assert something about the SHAPE of what it read.
    """
    src = _src()
    assert "SEMANTIC STALL" in src, (
        "no cycle-end check that the events read were actually parseable; "
        "a wrong-field query would look perfectly healthy"
    )
    i = src.index("SEMANTIC STALL")
    ctx = src[max(0, i - 900):i + 600]
    assert "parsed_ratio" in ctx and "events_read" in ctx
    assert "logger.error" in ctx, "a semantic stall must not be logged at INFO"
