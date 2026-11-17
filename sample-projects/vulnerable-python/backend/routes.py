# backend/routes.py
from fastapi import APIRouter, Request, HTTPException
from backend.services import UserService
from middleware.auth import verify_token

router = APIRouter(prefix="/api/users", tags=["users"])
user_service = UserService()

@router.get("/search")
def search_users_endpoint(request: Request, q: str = ""):
    """
    Source of untrusted data: query parameter 'q' comes directly from client
    and is passed without sanitization into UserService.
    """
    # UNTRUSTED INPUT: q is accepted directly from URL parameters
    user_query = q
    
    # Missing empty check / validation boundary
    # Directly forwarded to service layer
    results = user_service.search_users(user_query)
    
    return {"status": "success", "count": len(results), "results": results}

@router.get("/profile")
def get_user_profile(user_id: int):
    # Logic gap: No authorization check to ensure requester owns this profile
    # Edge case: No handling of negative user_id or zero
    profile = user_service.get_profile_by_id(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User not found")
    return profile

@router.post("/delete")
def delete_account(user_id: int):
    # Logic gap: missing CSRF / authorization validation
    return user_service.delete_user(user_id)
