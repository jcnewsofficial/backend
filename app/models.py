from sqlalchemy import Column, Integer, String, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    headline = Column(String)
    image_url = Column(String)
    category = Column(String)
    # Storing the 3 bullet points as a JSON list
    bullet_points = Column(JSON) 
    source_url = Column(String)
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    post_id = Column(Integer, ForeignKey("posts.id"))

    # 2. THIS IS THE MISSING PIECE:
    # It must match the back_populates name used in the Post class
    post = relationship("Post", back_populates="comments")
