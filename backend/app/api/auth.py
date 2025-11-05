from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

import bcrypt
from app.auth import get_auth_handler
from app.auth.handlers import AuthHandler
from app.mongodb import get_mongo_db
from app.schema import User

router = APIRouter()


token_auth_scheme = HTTPBearer()


@router.post("/login", tags=["auth"])
async def login(
    username: str = Form(...),
    password: str = Form(...),
    auth_handler: AuthHandler = Depends(get_auth_handler),
):
    """Login a user with username and password."""
    user = await auth_handler.authenticate_user(username, password)
    if user is None:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    # For now, just return the user ID
    # We'll implement proper session management later
    return JSONResponse(content={"user_id": user.user_id})


@router.post("/register", tags=["auth"])
async def register(
    username: str = Form(...),
    password: str = Form(...),
    db = Depends(get_mongo_db),
):
    """Register a new user with username and password."""
    # Check if username already exists
    existing_user = await db.user_login.find_one({"username": username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Create a new user in PostgreSQL
    # For now, we'll use the username as the sub
    from app.storage import get_or_create_user
    user, _ = await get_or_create_user(username)
    
    # Store user login info in MongoDB
    user_login = {
        "user_id": user.user_id,
        "username": username,
        "password_hash": password_hash,
    }
    await db.user_login.insert_one(user_login)
    
    return JSONResponse(content={"user_id": user.user_id, "username": username})

