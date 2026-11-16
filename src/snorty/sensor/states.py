from enum import Enum


class State(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    FAILED = "failed"


TRANSITIONS: dict[State, frozenset[State]] = {
    State.STOPPED: frozenset({State.STARTING}),
    # STARTING -> STARTING is a retry after a failed start attempt (backoff wait).
    State.STARTING: frozenset({State.RUNNING, State.STARTING, State.FAILED, State.STOPPING}),
    # RUNNING -> STARTING covers a crash, a network change and restart().
    State.RUNNING: frozenset({State.STARTING, State.STOPPING}),
    State.STOPPING: frozenset({State.STOPPED}),
    State.FAILED: frozenset({State.STARTING, State.STOPPED}),
}


class IllegalTransition(Exception):
    pass


def check_transition(old: State, new: State) -> None:
    if new not in TRANSITIONS[old]:
        raise IllegalTransition(f"{old.name} -> {new.name}")
