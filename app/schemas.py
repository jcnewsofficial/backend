from pydantic import BaseModel, EmailStr, HttpUrl, field_validator
from typing import List, Optional
from datetime import datetime

# --- COMMENT SCHEMAS ---

# Use this for nested data in comments/posts
class UserProfile(BaseModel):
    id: int
    username: str
    avatar_url: Optional[str] = None
    avatar_version: int = 1

    class Config:
        from_attributes = True

class CommentBase(BaseModel):
    content: str

class CommentCreate(CommentBase):
    post_id: int
    parent_id: Optional[int] = None

class Comment(CommentBase):
    id: int
    user_id: int
    post_id: int
    parent_id: Optional[int] = None
    timestamp: Optional[datetime] = None

    # CHANGED: Instead of flat fields, we use the author relationship
    author: Optional[UserProfile] = None

    replies: List['Comment'] = []

    class Config:
        from_attributes = True

# --- POST (NEWS) SCHEMAS ---

class PostBase(BaseModel):
    headline: str
    image_url: Optional[str] = None
    category: str
    bullet_points: List[str]
    source_url: Optional[str] = None # Using str instead of HttpUrl for more flexibility with DB strings
    source_name: Optional[str] = None

class PostCreate(PostBase):
    pass

class Post(PostBase):
    id: int
    comments: List[Comment] = []
    like_count: int = 0
    dislike_count: int = 0
    user_vote: Optional[int] = 0
    created_at: datetime
    views: int
    url: Optional[str] = None

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
    is_active: bool = True
    avatar_url: Optional[str] = None
    avatar_version: int = 1

    class Config:
        from_attributes = True

class VoteResponse(BaseModel):
    like_count: int
    dislike_count: int
    user_vote: int
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
