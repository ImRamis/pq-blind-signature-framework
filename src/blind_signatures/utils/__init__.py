"""
Utilities Module for the Blind Signatures Library.

This package contains helper functions for common tasks like serialization
that are used across different parts of the library and examples.
"""

from .serialization import EnhancedJSONEncoder, to_dict
from . import hash_utils

__all__ = [
    'EnhancedJSONEncoder',
    'to_dict',
    'hash_utils'
]