#!/usr/bin/env python3
"""API Routes for Authentication Services"""

from auth import Auth
from flask import Flask, jsonify, abort, request

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=['GET'], strict_slashes=False)
def hello() -> str:
    """return JSON payload"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=['POST'], strict_slashes=False)
def register_user() -> str:
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


@app.route("/sessions", methods=['POST'], strict_slashes=False)
def log_in() -> str:
    """
    login method to respond to the Post /session route
    the request is expected to contain form data with 'email'
    and 'password' fields.
    if login info is incorrect, use flask.abort with a 401 resp.
    """
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(404)

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)

    response = jsonify({'email': email, 'message': 'logged in'})

    response.set_cookie('session_id', session_id)

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
