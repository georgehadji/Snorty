import itertools

import pytest

from snorty.sensor.states import TRANSITIONS, IllegalTransition, State, check_transition

S = State
LEGAL = {
    (S.STOPPED, S.STARTING),
    (S.STARTING, S.RUNNING),
    (S.STARTING, S.STARTING),
    (S.STARTING, S.FAILED),
    (S.STARTING, S.STOPPING),
    (S.RUNNING, S.STARTING),
    (S.RUNNING, S.STOPPING),
    (S.STOPPING, S.STOPPED),
    (S.FAILED, S.STARTING),
    (S.FAILED, S.STOPPED),
}


def test_exactly_five_states() -> None:
    assert {s.name for s in State} == {"STOPPED", "STARTING", "RUNNING", "STOPPING", "FAILED"}


@pytest.mark.parametrize(("old", "new"), list(itertools.product(State, State)))
def test_every_pair_matches_the_spec_table(old: State, new: State) -> None:
    if (old, new) in LEGAL:
        check_transition(old, new)
    else:
        with pytest.raises(IllegalTransition):
            check_transition(old, new)


def test_table_and_expected_set_agree() -> None:
    assert {(o, n) for o, targets in TRANSITIONS.items() for n in targets} == LEGAL
