from typing import Any, Mapping, Sequence


def dict_filter_none(dct: Mapping[Any, Any]) -> dict:
    """Filter a dict to remove all items where the value is None"""
    return {k: v for k, v in dct.items() if v is not None}


def count_not_none(seq: Sequence[Any]) -> int:
    """Count the number of None values in a sequence"""
    return sum(0 if v is None else 1 for v in seq)


def ensure_mutually_exclusive(msg: str, *seq: Any) -> None:
    """
    Ensure only one value in a sequence is None.
    Raises ValueError with a supplied error message if more than one None value is found.
    """
    if count_not_none(seq) > 1:
        raise ValueError(msg)
