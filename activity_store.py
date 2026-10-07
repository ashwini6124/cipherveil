"""Supabase Auth and activity-log helpers for CipherVeil."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import requests


class ActivityStoreError(RuntimeError):
    """Raised when Supabase authentication or activity persistence fails."""


def _request(
    method: str,
    endpoint: str,
    api_key: str,
    *,
    payload: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
    prefer: str | None = None,
) -> Any:
    headers = {"apikey": api_key}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if prefer:
        headers["Prefer"] = prefer
    if "/rest/v1/" in endpoint:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        response = requests.request(
            method,
            endpoint,
            headers=headers,
            json=payload,
            params=params,
            timeout=15,
        )
    except requests.RequestException as error:
        raise ActivityStoreError(
            "Could not connect to Supabase. Check the project URL and network."
        ) from error

    try:
        response_data = response.json() if response.content else None
    except requests.JSONDecodeError:
        response_data = None

    if not response.ok:
        message = "Supabase request failed."
        if isinstance(response_data, dict):
            message = (
                response_data.get("msg")
                or response_data.get("message")
                or response_data.get("error_description")
                or response_data.get("error")
                or message
            )
        raise ActivityStoreError(str(message))

    return response_data


def _auth_url(project_url: str, path: str) -> str:
    return urljoin(f"{project_url.rstrip('/')}/", f"auth/v1/{path}")


def _rest_url(project_url: str, table: str) -> str:
    return urljoin(f"{project_url.rstrip('/')}/", f"rest/v1/{table}")


def register_account(
    project_url: str, anon_key: str, email: str, password: str
) -> dict[str, Any]:
    response = _request(
        "POST",
        _auth_url(project_url, "signup"),
        anon_key,
        payload={"email": email, "password": password},
    )
    if not isinstance(response, dict) or not isinstance(response.get("user"), dict):
        raise ActivityStoreError("Supabase did not return a user for this signup.")
    return response


def sign_in(
    project_url: str, anon_key: str, email: str, password: str
) -> dict[str, Any]:
    response = _request(
        "POST",
        _auth_url(project_url, "token?grant_type=password"),
        anon_key,
        payload={"email": email, "password": password},
    )
    if not isinstance(response, dict) or not isinstance(response.get("user"), dict):
        raise ActivityStoreError("Supabase did not return a user for this login.")
    return response


def record_activity(
    project_url: str,
    service_role_key: str,
    *,
    user_id: str,
    user_email: str,
    activity: str,
    operation: str = "",
    carrier: str = "",
    codec: str = "",
    cipher: str = "",
    payload_bits: int = 0,
    integrity: str = "",
) -> None:
    _request(
        "POST",
        _rest_url(project_url, "user_activity"),
        service_role_key,
        payload={
            "user_id": user_id,
            "user_email": user_email,
            "activity": activity,
            "operation": operation,
            "carrier": carrier,
            "codec": codec,
            "cipher": cipher,
            "payload_bits": payload_bits,
            "integrity": integrity,
        },
        prefer="return=minimal",
    )


def get_user_activity(
    project_url: str,
    service_role_key: str,
    user_id: str,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    response = _request(
        "GET",
        _rest_url(project_url, "user_activity"),
        service_role_key,
        params={
            "select": "created_at,activity,operation,carrier,codec,cipher,payload_bits,integrity",
            "user_id": f"eq.{user_id}",
            "order": "created_at.desc",
            "limit": str(limit + 1),
            "offset": str(offset),
        },
    )
    if not isinstance(response, list):
        raise ActivityStoreError("Supabase returned an invalid user activity response.")
    return response


def get_team_activity(
    project_url: str,
    service_role_key: str,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    response = _request(
        "GET",
        _rest_url(project_url, "user_activity"),
        service_role_key,
        params={
            "select": "created_at,user_email,activity,operation,carrier,codec,cipher,payload_bits,integrity",
            "order": "created_at.desc",
            "limit": str(limit + 1),
            "offset": str(offset),
        },
    )
    if not isinstance(response, list):
        raise ActivityStoreError("Supabase returned an invalid team activity response.")
    return response
