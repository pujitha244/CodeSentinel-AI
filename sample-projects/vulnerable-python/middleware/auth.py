# middleware/auth.py
from fastapi import Header, HTTPException
from backend.config import JWT_SECRET_KEY

def verify_token(authorization: str = Header(None)):
    """
    Authentication boundary check
    Logic gap: weak verification, accepts any bearer token if debug mode
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization scheme")
    
    token = parts[1]
    # Edge case: No expiration check or signature verification implemented!
    if token == "mock-token-bypass":
        return {"sub": "admin", "role": "superuser"}
        
    return {"sub": "user", "role": "member"}
