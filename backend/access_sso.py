"""Optional single sign-on through Cloudflare Access.

When Gamendar sits behind a Cloudflare Access application, Cloudflare adds a
signed JWT to every request it lets through (the Cf-Access-Jwt-Assertion
header). If both settings below are present we verify that token against the
team's public keys and sign in the active user whose email matches.

    CF_ACCESS_TEAM_DOMAIN  e.g. yourteam.cloudflareaccess.com
    CF_ACCESS_AUD          the application's "Application Audience (AUD) Tag"

Leave either unset and this is switched off. Password sign-in always keeps
working (for example on the LAN address, which bypasses Cloudflare).

Only the verified JWT is trusted. The plain Cf-Access-Authenticated-User-Email
header is never used, because anyone who can reach the container port directly
can set it.
"""
import os
import re

import jwt
from jwt import PyJWKClient

_TEAM_RE = re.compile(r'^[a-z0-9][a-z0-9-]*\.cloudflareaccess\.com$')
_jwks_clients = {}


def _team_domain():
    team = os.environ.get('CF_ACCESS_TEAM_DOMAIN', '').strip().lower()
    team = re.sub(r'^https?://', '', team).split('/')[0]
    if team and '.' not in team:
        team += '.cloudflareaccess.com'
    return team


def settings():
    """(team_domain, aud) when SSO is configured correctly, otherwise None."""
    team, aud = _team_domain(), os.environ.get('CF_ACCESS_AUD', '').strip()
    if not team or not aud:
        return None
    if not _TEAM_RE.match(team):
        print(f'WARNING: CF_ACCESS_TEAM_DOMAIN "{team}" is not a *.cloudflareaccess.com domain; SSO is off.')
        return None
    return team, aud


def enabled():
    return settings() is not None


def _jwks(team):
    client = _jwks_clients.get(team)
    if client is None:
        # PyJWKClient caches the key set and refetches when it sees an unknown key id (key rotation).
        client = PyJWKClient(f'https://{team}/cdn-cgi/access/certs', cache_keys=True, lifespan=12 * 3600)
        _jwks_clients[team] = client
    return client


def verified_email(request):
    """The email in a valid Cloudflare Access token on this request, lowercased, or None."""
    cfg = settings()
    token = request.headers.get('Cf-Access-Jwt-Assertion', '')
    if not cfg or not token:
        return None
    team, aud = cfg
    try:
        key = _jwks(team).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key,
            algorithms=['RS256'],
            audience=aud,
            issuer=f'https://{team}',
            leeway=30,
            options={'require': ['exp', 'iss', 'aud']},
        )
    except Exception as e:
        print(f'Cloudflare Access token rejected: {e}')
        return None
    email = (claims.get('email') or '').strip().lower()  # service tokens carry no email
    return email or None
