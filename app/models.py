from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, JSON, DateTime, UniqueConstraint, Text, Date
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

    comments = relationship("Comment", back_populates="author")
    likes = relationship("Like", back_populates="user")
    avatar_url = Column(String, nullable=True)
    avatar_version = Column(Integer, default=1)
    checkin_count = Column(Integer, default=0)
    last_checkin = Column(Date, nullable=True)

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    headline = Column(String)
    image_url = Column(String)
    category = Column(String)
    bullet_points = Column(JSON)
    source_url = Column(String)
    source_name = Column(String, nullable=True)
    url = Column(String)
    views = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")
    likes = relationship("Like", back_populates="post", cascade="all, delete-orphan")

# --- NEW: UserPost Model (Threads Style) ---
class UserPost(Base):
    __tablename__ = "user_posts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text, nullable=False)
    image_url = Column(String, nullable=True)
    topic = Column(String, nullable=True) # e.g. "Tech", "Life", "Rant"
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    author = relationship("User", backref="user_posts")
    # We reuse the existing Comment model but link it here
    comments = relationship("Comment", back_populates="user_post", cascade="all, delete-orphan")
    likes = relationship("UserPostLike", back_populates="user_post", cascade="all, delete-orphan")

class UserPostLike(Base):
    __tablename__ = "user_post_likes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    user_post_id = Column(Integer, ForeignKey("user_posts.id"))

    user = relationship("User")
    user_post = relationship("UserPost", back_populates="likes")

    __table_args__ = (UniqueConstraint('user_id', 'user_post_id', name='_user_userpost_uc'),)

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)

    # MODIFIED: post_id is now nullable to allow comments on UserPosts
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=True)

    # NEW: Link to UserPost
    user_post_id = Column(Integer, ForeignKey("user_posts.id"), nullable=True)

    user_id = Column(Integer, ForeignKey("users.id"))
    image_url = Column(String, nullable=True)
    parent_id = Column(Integer, ForeignKey("comments.id"), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    is_edited = Column(Boolean, default=False)

    author = relationship("User", back_populates="comments")

    # News Post Relationship
    post = relationship("Post", back_populates="comments")

    # User Post Relationship
    user_post = relationship("UserPost", back_populates="comments")

    parent = relationship("Comment", remote_side=[id], back_populates="replies")
    replies = relationship("Comment", back_populates="parent", cascade="all, delete-orphan")

    @property
    def username(self) -> str:
        return self.author.username if self.author else "User"

    @property
    def avatar_url(self) -> str:
        return self.author.avatar_url if self.author else None

    @property
    def avatar_version(self) -> int:
        return self.author.avatar_version if self.author else 1

# ... (Rest of existing models: CommentLike, Like, Message, Friendship, Notification) ...
class CommentLike(Base):
    __tablename__ = "comment_likes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    comment_id = Column(Integer, ForeignKey("comments.id"))
    vote_type = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User")
    comment = relationship("Comment")
    __table_args__ = (UniqueConstraint('user_id', 'comment_id', name='_user_comment_uc'),)

class Like(Base):
    __tablename__ = "likes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    post_id = Column(Integer, ForeignKey("posts.id"))
    vote_type = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User")
    post = relationship("Post")
    __table_args__ = (UniqueConstraint('user_id', 'post_id', name='_user_post_uc'),)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

class Friendship(Base):
    __tablename__ = "friendships"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    friend_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    requester = relationship("User", foreign_keys=[user_id])
    receiver = relationship("User", foreign_keys=[friend_id])

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    sender_id = Column(Integer, ForeignKey("users.id"))
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=True)
    # NEW: Allow notification to link to user_post
    user_post_id = Column(Integer, ForeignKey("user_posts.id"), nullable=True)
    comment_id = Column(Integer, ForeignKey("comments.id"), nullable=True)
    type = Column(String)
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", foreign_keys=[user_id], backref="notifications")
    sender = relationship("User", foreign_keys=[sender_id])
    post = relationship("Post")
