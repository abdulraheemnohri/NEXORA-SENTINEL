"""Bounded in-process session memory; not persisted across process restarts."""
from collections import deque


class ShortTermMemory:
    def __init__(self, capacity: int = 100):
        if type(capacity) is not int or not 1 <= capacity <= 10000:
            raise ValueError("memory_capacity_out_of_range")
        self._items = deque(maxlen=capacity)

    def add(self, role: str, content: str) -> None:
        if role not in {"user", "assistant", "system", "tool"} or not isinstance(content, str):
            raise ValueError("memory_record_invalid")
        self._items.append({"role": role, "content": content})

    def recent(self) -> list[dict]:
        return list(self._items)
