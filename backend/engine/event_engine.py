from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DisjoinWindow:
    first: dict
    second: dict
    third: dict
    duration_seconds: float

    @property
    def entries(self) -> list[dict]:
        return [self.first, self.second, self.third]

    @property
    def labels(self) -> str:
        return (
            f"A={self.first['mac']}@{self.first['timestamp']:.0f}, "
            f"B={self.second['mac']}@{self.second['timestamp']:.0f}, "
            f"C={self.third['mac']}@{self.third['timestamp']:.0f}"
        )


def unused_occurrences(occurrences: list[dict]) -> list[dict]:
    return [o for o in occurrences if not o["used"]]


def newest_candidate_window(unused: list[dict], batch_size: int) -> DisjoinWindow | None:
    if len(unused) < batch_size:
        return None
    first, second, third = unused[-3], unused[-2], unused[-1]
    return DisjoinWindow(
        first=first,
        second=second,
        third=third,
        duration_seconds=third["timestamp"] - first["timestamp"],
    )


def is_valid_window(window: DisjoinWindow, window_seconds: int) -> bool:
    return window.duration_seconds <= window_seconds


def mark_window_used(occurrences: list[dict], window: DisjoinWindow) -> int:
    used_timestamps = {entry["timestamp"] for entry in window.entries}
    marked = 0
    for occ in occurrences:
        if not occ["used"] and occ["timestamp"] in used_timestamps and marked < 3:
            occ["used"] = True
            marked += 1
    return marked

