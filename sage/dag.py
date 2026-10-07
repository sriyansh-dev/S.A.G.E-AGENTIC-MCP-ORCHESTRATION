"""asyncio DAG scheduler: single-responsibility nodes, parallel where dependencies allow."""
import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    skipped = "skipped"


class NonRetryable(Exception):
    """Raise from a node to fail immediately without retries."""


class DagError(ValueError):
    pass


@dataclass
class Node:
    name: str
    fn: Callable[[], Awaitable[Any]]
    deps: tuple[str, ...] = ()
    retries: int = 0
    timeout: float | None = None
    tolerate: frozenset[str] = frozenset()  # deps whose failure does NOT skip this node


@dataclass
class NodeResult:
    status: Status = Status.pending
    value: Any = None
    error: str | None = None
    duration_s: float = 0.0
    attempts: int = 0


@dataclass
class DagResult:
    nodes: dict[str, NodeResult] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return all(r.status == Status.succeeded for r in self.nodes.values())


class DagScheduler:
    def __init__(self, nodes: list[Node], *, max_concurrency: int = 4,
                 on_event: Callable[[str, Status, str | None], None] | None = None) -> None:
        self.nodes = {n.name: n for n in nodes}
        if len(self.nodes) != len(nodes):
            raise DagError("duplicate node names")
        self.max_concurrency = max_concurrency
        self.on_event = on_event or (lambda *_: None)
        self.validate()

    def validate(self) -> list[str]:
        indeg = {}
        for n in self.nodes.values():
            for d in n.deps:
                if d not in self.nodes:
                    raise DagError(f"{n.name} depends on unknown node {d}")
            indeg[n.name] = len(n.deps)
        order, ready = [], [k for k, v in indeg.items() if v == 0]
        while ready:
            cur = ready.pop()
            order.append(cur)
            for n in self.nodes.values():
                if cur in n.deps:
                    indeg[n.name] -= 1
                    if indeg[n.name] == 0:
                        ready.append(n.name)
        if len(order) != len(self.nodes):
            raise DagError("cycle detected: " + ", ".join(sorted(set(self.nodes) - set(order))))
        return order

    async def run(self) -> DagResult:
        res = DagResult({k: NodeResult() for k in self.nodes})
        done = {k: asyncio.Event() for k in self.nodes}
        sem = asyncio.Semaphore(self.max_concurrency)

        async def execute(node: Node) -> None:
            r = res.nodes[node.name]
            try:
                for d in node.deps:
                    await done[d].wait()
                bad = [d for d in node.deps if res.nodes[d].status != Status.succeeded and d not in node.tolerate]
                if bad:
                    r.status, r.error = Status.skipped, f"upstream not satisfied: {', '.join(bad)}"
                    self.on_event(node.name, r.status, r.error)
                    return
                async with sem:
                    r.status = Status.running
                    self.on_event(node.name, r.status, None)
                    t0 = time.monotonic()
                    for attempt in range(node.retries + 1):
                        r.attempts = attempt + 1
                        try:
                            coro = node.fn()
                            r.value = await (asyncio.wait_for(coro, node.timeout) if node.timeout else coro)
                            r.status, r.error = Status.succeeded, None
                            break
                        except NonRetryable as e:
                            r.status, r.error = Status.failed, str(e)
                            break
                        except asyncio.CancelledError:
                            raise
                        except Exception as e:  # noqa: BLE001
                            r.status = Status.failed
                            r.error = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
                            if attempt < node.retries:
                                await asyncio.sleep(min(20.0, 2.0**attempt))
                    r.duration_s = round(time.monotonic() - t0, 2)
                    self.on_event(node.name, r.status, r.error)
            finally:
                done[node.name].set()

        tasks = [asyncio.create_task(execute(n), name=n.name) for n in self.nodes.values()]
        try:
            await asyncio.gather(*tasks)
        except BaseException:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return res
