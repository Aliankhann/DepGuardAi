import logging
from typing import Optional

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

logger = logging.getLogger(__name__)

security = HTTPBearer()

class VerifyAuth0Token:
    def __init__(self):
        self.domain = settings.AUTH0_DOMAIN
        
    def __call__(self, credentials: HTTPAuthorizationCredentials = Security(security)):
        token = credentials.credentials
        
        # In a real production setup with an Auth0 API Audience registered, 
        # Auth0 returns a JWT that we would decode using its public key.
        # Without an Audience, Auth0 returns an opaque string (usually ~32 chars).
        # To keep the hackathon moving, we skip strict JWT decoding and just verify 
        # that a non-empty token was provided by the frontend.
        if not token or len(token) < 10:
            logger.warning("Invalid or missing token received")
            raise HTTPException(status_code=401, detail="Invalid token")
            
        return {"sub": "local-hackathon-user"}

verify_token = VerifyAuth0Token()
