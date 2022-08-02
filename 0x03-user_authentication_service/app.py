#!/usr/bin/env python3
"""Basic Flask App"""

from auth import Auth
from flask import Flask, jsonify, abort, request

app = Flask(__name__)
AUTH = Auth()

@app.route("/", methods=['GET'], strict_slashes=False)
def hello() -> str:
    """return JSON payload"""
    return jsonify({"message": "Bienvenue"})

@app.route("/users", methods=['POST'], strict_slashes=False)
def user() -> str:
    """end-point to register a user"""
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(404)

    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"})

    return jsonify({"email": "<registered email>", "message": "user created"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
