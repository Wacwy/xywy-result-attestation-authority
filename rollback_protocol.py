#!/usr/bin/env python3
"""Executable model for a fail-closed checkpoint rollback protocol.

This is a TEST_FIXTURE_ONLY model.  The ``Anchor`` represents a genuinely
rollback-resistant, independently administered monotonic service.  A local
file, database, second process, signature, or hash chain is *not* an Anchor.

Safety order is intentional:

1. all checkpoint replicas and the anchor must expose the same head;
2. the anchor atomically CAS-commits the verified successor first;
3. checkpoint replicas catch up to the anchor;
4. an ALLOW result is possible only after a new unanimous read.

A crash after (2) wedges the gate closed but is recoverable from the anchor.
Replacing every checkpoint store with an old, internally consistent snapshot
therefore cannot reopen a sibling while the anchor remains authoritative.
"""
from __future__ import annotations

from dataclasses import dataclass


class Reject(Exception):
    pass


@dataclass(frozen=True, order=True)
class Head:
    size: int
    root: str

    def __post_init__(self) -> None:
        if self.size < 1 or len(self.root) != 64 or any(
                c not in "0123456789abcdef" for c in self.root):
            raise ValueError("invalid head")


class Store:
    """Rollbackable checkpoint store used by the hostile model."""

    def __init__(self, head: Head):
        self.head = head

    def cas(self, before: Head, after: Head) -> None:
        if self.head != before or after.size <= before.size:
            raise Reject("checkpoint CAS")
        self.head = after

    def recover_to_anchor(self, anchor_head: Head) -> None:
        # Recovery may only advance; it may never overwrite a conflicting head.
        if self.head.size >= anchor_head.size and self.head != anchor_head:
            raise Reject("checkpoint conflicting head")
        self.head = anchor_head


class Anchor:
    """Abstract monotonic CAS service; deployment must supply the real thing."""

    def __init__(self, head: Head):
        self._head = head

    @property
    def head(self) -> Head:
        return self._head

    def cas(self, before: Head, after: Head) -> None:
        if self._head != before or after.size <= before.size:
            raise Reject("anchor CAS")
        self._head = after


class Gate:
    def __init__(self, stores: list[Store], anchor: Anchor):
        if len(stores) < 2:
            raise ValueError("at least two checkpoint stores")
        self.stores = stores
        self.anchor = anchor

    def current(self) -> Head:
        heads = [store.head for store in self.stores]
        heads.append(self.anchor.head)
        if len(set(heads)) != 1:
            raise Reject("split or rollback view")
        return heads[0]

    def commit(self, before: Head, after: Head, *, crash_after_anchor=False,
               crash_after_store: int | None = None) -> None:
        if self.current() != before or after.size <= before.size:
            raise Reject("not a current-head successor")
        self.anchor.cas(before, after)
        if crash_after_anchor:
            raise RuntimeError("simulated crash after anchor commit")
        for index, store in enumerate(self.stores):
            store.cas(before, after)
            if crash_after_store == index:
                raise RuntimeError("simulated crash during checkpoint fanout")
        if self.current() != after:
            raise Reject("post-commit unanimity")

    def recover(self) -> Head:
        anchor_head = self.anchor.head
        for store in self.stores:
            store.recover_to_anchor(anchor_head)
        return self.current()

