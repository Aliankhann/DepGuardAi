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
        
    def __call__(self, credentials: HTTPAuthorizationCredentials = Security(security)):
        token = credentials.credentials
        print(f"DEBUG: Received token: {token[:20]}...{token[-20:]}")
        
        # In a real production setup with an Audience, Auth0 returns a JWT that we decode here.
        # But without an Audience attached, Auth0 returns an opaque string (e.g. 32 chars).
        # For the hackathon, we will just ensure a token was passed.
        if not token or len(token) < 10:
            raise HTTPException(status_code=401, detail="Invalid token")
            
        return {"sub": "local-hackathon-user"}

verify_token = VerifyAuth0Token()
