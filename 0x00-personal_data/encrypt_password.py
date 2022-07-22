#!/usr/bin/env python3
"""Encrypting passwords"""

import bcrypt


def hash_password(password: str) -> bcrypt.gensalt:
    """returns a salted, hashed password, which is a byte string"""
    password = b""
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    return hashed
