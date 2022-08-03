#!/usr/bin/env python3
"""API Routes for Authentication Services"""

from crypt import methods
from auth import Auth
from flask import Flask, jsonify, abort, redirect, request

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


@app.route("/sessions", methods=['DELETE'])
def log_out():
    """logout function to respond to the DELETE /sessions route.
    The request is expected to contain the session ID as a cookie
    with key 'session_id'.
    If the user exists destroy the session and redirect the user to GET /.
    If the user does not exist, respond with a 403 HTTP status.
    """
    session_id = request.cookies.get("session_id", None)

    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect('/')


@app.route("/profile", methods=['GET'])
def profile() -> str:
    """profile function to respond to the GET /profile route.
    The request is expected to contain a session_id cookie
    If the user exist, respond with a 200 HTTP status and the
    following JSON payload:
        {"email": "<user email>"}
    """
    session_id = request.cookies.get('session_id', None)

    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    return jsonify({"email": user.email}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
