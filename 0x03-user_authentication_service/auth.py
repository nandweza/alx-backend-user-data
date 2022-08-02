#!/usr/bin/env python3
"""Hash password"""

import bcrypt


def _hash_password(password: str) -> bytes:
    """
    takes in a password string arguments
    Returns: bytes
    """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed
