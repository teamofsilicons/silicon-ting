#!/usr/bin/env python3
"""Check deployed IAM 5 browser redirects and callback boundaries without credentials."""
import argparse
import http.client
import json
from urllib.parse import parse_qs, urlencode, urlsplit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--url", default="https://ting.teamofsilicons.com")
args = parser.parse_args()
origin = urlsplit(args.url)
assert origin.scheme == "https" and not origin.username and not origin.query


def request(path):
    connection = http.client.HTTPSConnection(origin.hostname, origin.port or 443, timeout=30)
    try:
        connection.request("GET", path, headers={"User-Agent": "ting-iam5-smoke/1"})
        response = connection.getresponse()
        raw = response.read()
        return response.status, dict(response.getheaders()), raw
    finally:
        connection.close()


for kind in ("carbon", "silicon"):
    for popup in (False, True):
        query = {"identity_kind": kind, "next": "/#apps"}
        if popup:
            query["popup_nonce"] = "a" * 64
        status, headers, _ = request("/v1/session/login?" + urlencode(query))
        headers = {key.lower(): value for key, value in headers.items()}
        assert status == 302, (kind, popup, status)
        target = urlsplit(headers["location"])
        params = parse_qs(target.query)
        assert target.scheme == "https" and target.netloc == "auth.iam.teamofsilicons.com"
        assert target.path == "/login" and params["app_id"] == ["ting"]
        assert params["identity_kind"] == [kind]
        assert params.get("display") == (["popup"] if popup else None)
        callback = urlsplit(params["redirect_uri"][0])
        assert callback.netloc == origin.netloc and callback.path == "/v1/session/callback"
        state = parse_qs(callback.query)["state"][0]
        assert len(state) >= 32
        cookie = headers["set-cookie"]
        assert cookie.startswith("ting_login=" + state + ";")
        assert all(value in cookie for value in ("HttpOnly", "Secure", "SameSite=Lax"))
        denied, _, raw = request(callback.path + "?" + urlencode({"state": state, "slt": "invalid"}))
        assert denied == 403 and json.loads(raw)["error"]["code"] == "permission_denied"
        print(json.dumps({"check": kind + (" popup" if popup else " full page"), "passed": True}))

for query in ({"identity_kind": "invalid"}, {"identity_kind": "carbon", "popup_nonce": "short"},
              {"identity_kind": "carbon", "next": "//untrusted.example"}):
    status, _, raw = request("/v1/session/login?" + urlencode(query))
    assert status == 400 and json.loads(raw)["error"]["code"] == "invalid_input"
print(json.dumps({"check": "invalid kind, nonce and return destination rejected", "passed": True}))
status, _, raw = request("/v1/session/catalog/callback?" + urlencode({"org_id": "tos", "request_id": "invalid", "state": "invalid", "authorization_id": "invalid"}))
assert status == 401 and json.loads(raw)["error"]["code"] == "authentication_required"
print(json.dumps({"check": "catalog callback requires authenticated session", "passed": True}))
