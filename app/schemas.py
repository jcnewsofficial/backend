from pydantic import BaseModel, EmailStr, HttpUrl, field_validator
from typing import List, Optional
from datetime import datetime

# --- COMMENT SCHEMAS ---

class CommentBase(BaseModel):
    content: str

class CommentCreate(CommentBase):
    post_id: int

class Comment(CommentBase):
    id: int
    user_id: int
    post_id: int
    timestamp: Optional[datetime] = None
    username: str # This name MUST match the @property name in models.py

    class Config:
        from_attributes = True # This allows Pydantic to read properties from SQLAlchemy models

# --- POST (NEWS) SCHEMAS ---

class PostBase(BaseModel):
    headline: str
    image_url: str
    category: str
    bullet_points: List[str]
    source_url: Optional[str] = None # Using str instead of HttpUrl for more flexibility with DB strings

class PostCreate(PostBase):
    pass

class Post(PostBase):
    id: int
    comments: List[Comment] = [] # Tell Pydantic to include the list of comments

    class Config:
        from_attributes = True


# --- USER SCHEMAS ---

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    # FIX: Set default to True so FastAPI doesn't crash if DB doesn't return it immediately
    is_active: bool = True

    class Config:
        from_attributes = True


# --- AUTH SCHEMAS ---

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


# --- LIKE SCHEMAS (New) ---

class LikeBase(BaseModel):
    post_id: int

class Like(LikeBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True
