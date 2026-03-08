import logging
import time
from typing import Optional

import httpx
import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

logger = logging.getLogger(__name__)

security = HTTPBearer()

# JWKS cache: (keys_list, fetched_at_epoch_monotonic)
_jwks_cache: Optional[tuple[list, float]] = None
_JWKS_TTL_SECONDS = 43200  # 12 hours — proactive refresh, not just on rotation


async def _fetch_jwks(domain: str) -> list:
    """Fetch JWKS from Auth0 asynchronously — non-blocking."""
    url = f"https://{domain}/.well-known/jwks.json"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()["keys"]


async def _get_jwks(domain: str, force_refresh: bool = False) -> list:
    """Return cached JWKS keys, refreshing on TTL expiry or when forced.

    force_refresh=True is used when the token's kid is not found in the cache,
    which indicates Auth0 has rotated its signing keys since the last fetch.
    """
    global _jwks_cache
    now = time.monotonic()
    if (
        not force_refresh
        and _jwks_cache is not None
        and (now - _jwks_cache[1]) < _JWKS_TTL_SECONDS
    ):
        return _jwks_cache[0]

    keys = await _fetch_jwks(domain)
    _jwks_cache = (keys, now)
    return keys


def _find_rsa_key(keys: list, kid: str) -> dict:
    for key in keys:
        if key.get("kid") == kid:
            return {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    return {}


class VerifyAuth0Token:
    def __init__(self):
        self.domain = settings.AUTH0_DOMAIN
        self.audience = settings.AUTH0_API_AUDIENCE
        self.algorithms = ["RS256"]
        self.issuer = f"https://{self.domain}/"

    async def __call__(
        self, credentials: HTTPAuthorizationCredentials = Security(security)
    ) -> dict:
        token = credentials.credentials
        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token header")

        kid = unverified_header.get("kid", "")

        # First attempt: use cached JWKS
        keys = await _get_jwks(self.domain)
        rsa_key = _find_rsa_key(keys, kid)

        # kid not in cache → Auth0 may have rotated keys → force one refresh
        if not rsa_key:
            logger.info("kid %s not in cached JWKS — force-refreshing for key rotation", kid)
            keys = await _get_jwks(self.domain, force_refresh=True)
            rsa_key = _find_rsa_key(keys, kid)

        if not rsa_key:
            raise HTTPException(status_code=401, detail="Unable to find appropriate key")

        try:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(rsa_key)
            payload = jwt.decode(
                token,
                public_key,
                algorithms=self.algorithms,
                audience=self.audience if self.audience else None,
                issuer=self.issuer,
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


verify_token = VerifyAuth0Token()
