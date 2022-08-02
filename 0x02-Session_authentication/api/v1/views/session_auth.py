#!/usr/bin/env python3
"""Handles all routes for the Session authentication"""

from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route("/auth_session/login", methods=['POST'], strictslashes=False)
def login():
    """login session route"""
    
    email = request.form.get('email')
    if not email:
        return jsonify({ "error": "email missing" }), 400
    
    password = request.form.get('password')
    if not password:
        return jsonify({ "error": "password missing" }), 400

    try:
        found_users = User.search({'email': email})
    except Exception:
        return jsonify({ "error": "no user found for this email" }), 404

    if not found_users:
        return jsonify({ "error": "no user found for this email" }), 404

    for user in found_users:
        if not user.is_valid_password(password):
            return jsonify({ "error": "wrong password" }), 401

    from api.v1.app import auth

    user = found_users[0]
    session_id = auth.create_session(user.id)

    SESSION_NAME = getenv("SESSION_NAME")

    response = jsonify(user.to_json())
    response.set_cookie(SESSION_NAME, session_id)

    return response

@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strictslashes=False)
def logout():
    """logouts user and deletes user session
    Returns Empty dict if successful
    """

    from api.v1.app import auth

    del_user = auth.destroy_session(request)

    if not del_user:
        abort(404)

    return jsonify({}), 200