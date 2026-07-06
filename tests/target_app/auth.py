"""
OAuth2 + JWT Authentication Module for VAA Cyber-range v2
Provides enterprise-grade authentication with JWT tokens and bcrypt password hashing
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Optional
import sqlite3


SECRET_KEY = "VAA_SECRET_KEY_CHANGE_IN_PRODUCTION_d8f7a9b2c4e1f3a5"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password using bcrypt
    
    Args:
        plain_password: Plain text password from user
        hashed_password: Bcrypt hashed password from database
        
    Returns:
        True if password matches, False otherwise
    """
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt
    
    Args:
        password: Plain text password
        
    Returns:
        Bcrypt hashed password as string
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token
    
    Args:
        data: Payload data to encode in token (e.g., {"sub": "username", "role": "admin"})
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Validate JWT token and extract current user information
    
    Args:
        token: JWT token from Authorization header
        
    Returns:
        Dictionary with user information {"username": str, "role": str}
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        
        if username is None:
            raise credentials_exception
            
        return {"username": username, "role": role}
        
    except JWTError:
        raise credentials_exception


async def get_current_admin_user(current_user: dict = Depends(get_current_user)) -> dict:
    """
    Verify that current user has admin role
    
    Args:
        current_user: User dict from get_current_user
        
    Returns:
        User dict if admin
        
    Raises:
        HTTPException: If user is not admin
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


def authenticate_user(db_conn: sqlite3.Connection, username: str, password: str) -> Optional[dict]:
    """
    Authenticate a user against the database
    
    Args:
        db_conn: SQLite database connection
        username: Username to authenticate
        password: Plain text password
        
    Returns:
        User dict if authentication successful, None otherwise
    """
    c = db_conn.cursor()
    c.execute("SELECT id, username, password, role, email FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    
    if not user:
        return None
    

    if not verify_password(password, user[2]):
        return None
    
    return {
        "id": user[0],
        "username": user[1],
        "role": user[3],
        "email": user[4]
    }
