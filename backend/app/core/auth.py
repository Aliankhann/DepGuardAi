import jwt
from fastapi import HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
import httpx
from typing import Optional

# Setup HTTP Bearer scheme
security = HTTPBearer()

def get_auth0_jwks(domain: str):
    """Fetch JSON Web Key Set from Auth0"""
    jwks_url = f"https://{domain}/.well-known/jwks.json"
    with httpx.Client() as client:
        response = client.get(jwks_url)
        response.raise_for_status()
        return response.json()

class VerifyAuth0Token:
    def __init__(self):
        self.domain = settings.AUTH0_DOMAIN
        self.audience = settings.AUTH0_API_AUDIENCE
        self.algorithms = ["RS256"]
        self.issuer = f"https://{self.domain}/"
        self.jwks = None

    def _get_jwks(self):
        if not self.jwks:
            self.jwks = get_auth0_jwks(self.domain)
        return self.jwks

    def __call__(self, credentials: HTTPAuthorizationCredentials = Security(security)):
        token = credentials.credentials
        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token header")
        
        rsa_key = {}
        jwks = self._get_jwks()
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                # Construct key from JWK parts
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(rsa_key)
                
                payload = jwt.decode(
                    token,
                    public_key,
                    algorithms=self.algorithms,
                    audience=self.audience if self.audience else None,
                    issuer=self.issuer
                )
                return payload
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Token has expired")
            except jwt.InvalidTokenError as e:
                raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
        
        raise HTTPException(status_code=401, detail="Unable to find appropriate key")

verify_token = VerifyAuth0Token()
