from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, JSON, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    # This matches your schemas.py requirement
    is_active = Column(Boolean, default=True)

    # Relationships: A user can have many comments and many likes
    comments = relationship("Comment", back_populates="author")
    likes = relationship("Like", back_populates="user")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    headline = Column(String)
    image_url = Column(String)
    category = Column(String)
    bullet_points = Column(JSON) # List of strings
    source_url = Column(String)

    # Relationships
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")
    likes = relationship("Like", back_populates="post", cascade="all, delete-orphan")
    views = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    post_id = Column(Integer, ForeignKey("posts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))

    # NEW: Self-referencing relationship
    parent_id = Column(Integer, ForeignKey("comments.id"), nullable=True)

    # server_default=func.now() tells Postgres to handle the time itself
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    author = relationship("User", back_populates="comments")
    post = relationship("Post", back_populates="comments")

    # NEW: Relationship to fetch replies
    replies = relationship("Comment", backref=backref('parent', remote_side=[id]), cascade="all, delete-orphan")

    @property
    def username(self) -> str:
        if self.author:
            return self.author.username
        return "User"

class Like(Base):
    __tablename__ = "likes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    post_id = Column(Integer, ForeignKey("posts.id"))
    vote_type = Column(Integer)

    # ADD THESE RELATIONSHIPS
    user = relationship("User")
    post = relationship("Post")

    __table_args__ = (UniqueConstraint('user_id', 'post_id', name='_user_post_uc'),)
