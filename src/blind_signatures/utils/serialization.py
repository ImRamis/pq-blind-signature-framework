"""
Provides utilities for serializing complex cryptographic data types.
"""

import json
from dataclasses import dataclass, is_dataclass, asdict

class EnhancedJSONEncoder(json.JSONEncoder):
    """
    A custom JSON encoder that can handle dataclasses, bytes,
    and py_ecc finite field elements, which are not standard JSON types.
    """
    def default(self, o):
        if is_dataclass(o):
            return {k: self.default(v) for k, v in asdict(o).items()}
        if isinstance(o, bytes):
            return o.hex()
        # For FQ elements from py_ecc (e.g., in Hanzlik scheme)
        if hasattr(o, 'n'):
            return int(o.n)
        # For FQ2 elements from py_ecc
        if hasattr(o, 'coeffs'):
            return [self.default(c) for c in o.coeffs]
        # Generic iterables
        if isinstance(o, (list, tuple)):
            return [self.default(v) for v in o]
        if isinstance(o, dict):
            return {k: self.default(v) for k, v in o.items()}
        # Primitives
        if isinstance(o, (str, int, float, bool)) or o is None:
            return o
        return super().default(o)

def to_dict(obj: any) -> dict:
    """
    Helper function to convert a Python object (including dataclasses and
    crypto types) into a dictionary using the enhanced encoder.
    """
    return json.loads(json.dumps(obj, cls=EnhancedJSONEncoder))