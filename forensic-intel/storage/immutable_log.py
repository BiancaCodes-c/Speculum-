"""Immutable security log.

Append-only, hash-chained security log. Each entry carries the
hash of the one before it, so an edited or deleted entry breaks
the chain and shows itself.
"""

from __future__ import annotations


class ImmutableLog:
    """TODO: implement."""

    pass

def append_entry(*args, **kwargs):
    """TODO: implement."""
    raise NotImplementedError

def verify_chain(*args, **kwargs):
    """TODO: implement."""
    raise NotImplementedError
