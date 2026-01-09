import asyncio
from fastapi import FastAPI, Depends, HTTPException, Response, status, Header, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func, or_
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from . import models, schemas, database
from .scraper import auto_parse_news
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, get_db, SessionLocal
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from .models import User
from fastapi.staticfiles import StaticFiles

import shutil
import os
import glob

# --- SECURITY CONFIGURATION ---
SECRET_KEY = "DEVELOPMENT_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 week

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

# --- DB INIT ---
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="JC News Backend")
app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- SECURITY UTILS ---
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

def get_optional_current_user(token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Helper to identify user if token is present, but not fail if it isn't."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email:
            return db.query(models.User).filter(models.User.email == email).first()
    except JWTError:
        return None
    return None

def get_cbc_links():
    url = "https://www.cbc.ca/news"
    # Modern headers to avoid being blocked
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')

        links = []
        # CBC uses a specific class for their primary story links
        # We look for all anchor tags
        for a in soup.find_all('a', href=True):
            href = a['href']

            # Pattern check:
            # 1. Must contain /news/
            # 2. Usually ends with a pattern like 1.7034234 (the ID)
            # 3. We ignore links to category sections (like just /news/world)
            if "/news/" in href and any(char.isdigit() for char in href):
                # Clean up relative URLs
                if href.startswith('/'):
                    full_url = f"https://www.cbc.ca{href}"
                elif href.startswith('http'):
                    full_url = href
                else:
                    continue

                # Filter out duplicates and non-story links (like 'top-news' index)
                if full_url not in links and "desktop-top-navigation" not in full_url:
                    links.append(full_url)

        print(f"Found {len(links)} potential articles.")
        return links[:5]

    except Exception as e:
        print(f"Error fetching CBC links: {e}")
        return []

def extract_category_from_url(url):
    try:
        # 1. Parse the URL
        path = urlparse(url).path  # Result: "/news/world/some-story-1.123"

        # 2. Split by slashes and remove empty strings
        parts = [p for p in path.split('/') if p]

        # 3. Logic for CBC structure:
        # parts[0] is usually 'news'
        # parts[1] is usually the category (world, canada, politics, etc.)
        if len(parts) >= 2 and parts[0] == 'news':
            category = parts[1]
            return category.capitalize() # Returns "World", "Canada", etc.

        return "General" # Fallback if structure is different
    except Exception:
        return "General"

async def scrape_cbc_periodically():
    while True:
        db = SessionLocal()
        try:
            article_links = get_cbc_links()
            for link in article_links:
                exists = db.query(models.Post).filter(models.Post.url == link).first()
                if exists: continue
                print(link)
                # PARSE CATEGORY AUTOMATICALLY
                auto_category = extract_category_from_url(link)
                scraped_data = auto_parse_news(link)
                if scraped_data:
                    new_post = models.Post(
                        headline=scraped_data["headline"],
                        image_url=scraped_data.get("image_url"),
                        category=auto_category, # <--- USED HERE
                        bullet_points=scraped_data["bullets"],
                        url=link,
                        source_url=link
                    )
                    db.add(new_post)
                    db.commit()
        except Exception as e:
            print(f"SCRAPER CRASHED: {e}")
        finally:
            db.close()
        await asyncio.sleep(600)

# Start the task when FastAPI starts
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(scrape_cbc_periodically())

# --- AUTH ENDPOINTS ---

@app.post("/register", response_model=schemas.User)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=get_password_hash(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Store email in 'sub' to match get_current_user logic
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- NEWS & FEED ENDPOINTS ---

@app.get("/feed", response_model=List[schemas.Post])
def read_posts(
    sort: str = "newest",           # newest, liked, viewed
    category: Optional[str] = None, # All, Tech, Politics, etc.
    time: str = "all",              # 24h, week, month, year, all
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
):
    # 1. Start the query with eager loading for comments and authors
    query = db.query(models.Post).options(
        joinedload(models.Post.comments).joinedload(models.Comment.author)
    )

    # 2. Apply Category Filter
    if category and category != "All":
        query = query.filter(models.Post.category.ilike(category))

    # 3. Apply Time Range Filter (Only for Liked or Viewed)
    # This prevents old viral posts from staying at the top forever
    if sort in ["liked", "viewed"] and time != "all":
        now = datetime.utcnow()
        if time == "24h":
            start_date = now - timedelta(hours=24)
        elif time == "week":
            start_date = now - timedelta(weeks=1)
        elif time == "month":
            start_date = now - timedelta(days=30)
        elif time == "year":
            start_date = now - timedelta(days=365)
        else:
            start_date = None

        if start_date:
            query = query.filter(models.Post.created_at >= start_date)

    # 4. Apply Sorting Logic
    if sort == "liked":
        # 1. Subquery to count positive votes
        like_counts = db.query(
            models.Like.post_id,
            func.count(models.Like.id).label('total_likes')
        ).filter(models.Like.vote_type == 1).group_by(models.Like.post_id).subquery()

        # 2. Join the subquery
        query = query.outerjoin(like_counts, models.Post.id == like_counts.c.post_id)

        # 3. Use COALESCE to treat NULL as 0
        # This ensures 1 like > 0 likes (instead of NULL breaking the sort)
        query = query.order_by(
            desc(func.coalesce(like_counts.c.total_likes, 0)),
            desc(models.Post.created_at)
        )

    elif sort == "viewed":
        # Assumes you have a 'views' column in your Post model
        query = query.order_by(desc(models.Post.views), desc(models.Post.created_at))

    else:
        # Default: Newest (Sorting by ID is often the same as Date but faster)
        query = query.order_by(desc(models.Post.created_at))

    # 5. Execute Query
    posts = query.all()

    # 6. Post-process counts and user-specific votes
    for post in posts:
        # Get count of Likes (1)
        post.like_count = db.query(models.Like).filter(
            models.Like.post_id == post.id,
            models.Like.vote_type == 1
        ).count()

        # Get count of Dislikes (-1)
        post.dislike_count = db.query(models.Like).filter(
            models.Like.post_id == post.id,
            models.Like.vote_type == -1
        ).count()

        # Check if the logged-in user has voted on this specific post
        post.user_vote = 0
        if current_user:
            vote = db.query(models.Like).filter(
                models.Like.post_id == post.id,
                models.Like.user_id == current_user.id
            ).first()
            if vote:
                post.user_vote = vote.vote_type

    return posts

@app.get("/news/search")
def search_news(
    q: Optional[str] = None,
    category: Optional[str] = None,
    time: Optional[str] = "all", # Options: "24h", "week", "month", "all"
    db: Session = Depends(get_db)
):
    # 1. Start with a base query on the Post model
    query = db.query(models.Post)

    # 2. Filter by Keyword (Headline)
    if q:
        query = query.filter(models.Post.headline.ilike(f"%{q}%"))

    # 3. Filter by Category
    if category and category != "All":
        query = query.filter(models.Post.category == category)

    # 4. Filter by Time Range
    if time != "all":
        now = datetime.utcnow()
        if time == "24h":
            start_date = now - timedelta(hours=24)
        elif time == "week":
            start_date = now - timedelta(days=7)
        elif time == "month":
            start_date = now - timedelta(days=30)

        query = query.filter(models.Post.created_at >= start_date)

    # 5. Execute and return (limit to 20 for search performance)
    results = query.order_by(desc(models.Post.created_at)).limit(20).all()

    return results

@app.post("/auto-scrape", status_code=201)
async def create_automated_post(url: str, category: str, db: Session = Depends(get_db)):
    try:
        scraped_data = auto_parse_news(url)
        new_post = models.Post(
            headline=scraped_data["headline"],
            image_url=scraped_data.get("image_url", "https://example.com/default.jpg"),
            category=category,
            bullet_points=scraped_data["bullets"],
            # Ensure the database field 'url' is populated
            url=url,
            # You can keep source_url if your model has both,
            # but 'url' is what the feed query was crashing on.
            source_url=url
        )
        db.add(new_post)
        db.commit()
        db.refresh(new_post)
        return {"status": "success", "post_id": new_post.id}
    except Exception as e:
        db.rollback() # Good practice to rollback on failure
        raise HTTPException(status_code=500, detail=str(e))

# --- SOCIAL ENDPOINTS ---

@app.post("/comments", response_model=schemas.Comment)
def create_comment(
    comment: schemas.CommentCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    new_comment = models.Comment(
        content=comment.content,
        post_id=comment.post_id,
        user_id=current_user.id,
        parent_id=comment.parent_id
    )
    db.add(new_comment)
    db.commit()

    # Eagerly load the author so the response includes username/avatar_url
    db_comment = db.query(models.Comment).options(
        joinedload(models.Comment.author)
    ).filter(models.Comment.id == new_comment.id).first()

    return db_comment

@app.post("/posts/{post_id}/vote")
def vote_post(
    post_id: int,
    vote_type: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    existing_vote = db.query(models.Like).filter(
        models.Like.post_id == post_id,
        models.Like.user_id == current_user.id
    ).first()

    if existing_vote:
        if existing_vote.vote_type == vote_type:
            db.delete(existing_vote)
        else:
            existing_vote.vote_type = vote_type
    else:
        new_vote = models.Like(user_id=current_user.id, post_id=post_id, vote_type=vote_type)
        db.add(new_vote)

    db.commit()
    return {"status": "success"}

@app.get("/posts/{post_id}", response_model=schemas.Post)
def get_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
):
    # 1. Fetch post with comments and authors pre-loaded
    post = db.query(models.Post).options(
        joinedload(models.Post.comments).joinedload(models.Comment.author)
    ).filter(models.Post.id == post_id).first()

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # 2. Increment view count (Logic for the "Most Viewed" sort)
    post.views = (post.views or 0) + 1
    db.commit()
    db.refresh(post)

    # 3. Calculate social counts
    post.like_count = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.vote_type == 1).count()
    post.dislike_count = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.vote_type == -1).count()

    # 4. Check if current user has voted
    post.user_vote = 0
    if current_user:
        vote = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.user_id == current_user.id).first()
        if vote:
            post.user_vote = vote.vote_type

    return post

@app.post("/messages/send")
def send_message(receiver_id: int, content: str, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # 1. THE "LOL" CHECK: Prevent self-messaging
    if current_user.id == receiver_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot message yourself."
        )

    receiver = db.query(models.User).filter(models.User.id == receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")

    print(content)
    new_msg = models.Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content,
        timestamp=datetime.utcnow()
    )
    db.add(new_msg)
    db.commit()
    return {"status": "sent"}

# --- ADD THIS TO main.py ---

@app.get("/messages/conversation/{other_user_id}")
def get_conversation(
    other_user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # This query gets the full history between you and the other person
    messages = db.query(models.Message).filter(hg
        ((models.Message.sender_id == current_user.id) & (models.Message.receiver_id == other_user_id)) |
        ((models.Message.sender_id == other_user_id) & (models.Message.receiver_id == current_user.id))
    ).order_by(models.Message.timestamp.asc()).all()

    # Format the messages so the frontend can read them easily
    return [
        {
            "id": m.id,
            "content": m.content,
            "sender_id": m.sender_id,
            "receiver_id": m.receiver_id,
            "timestamp": m.timestamp.isoformat()
        } for m in messages
    ]

@app.get("/users/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "avatar_url": current_user.avatar_url,
        "avatar_version": current_user.avatar_version or 1 # Key for cache busting
    }

@app.get("/messages/inbox")
def get_inbox(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    messages = db.query(models.Message).options(
        joinedload(models.Message.sender),
        joinedload(models.Message.receiver)
    ).filter(
        (models.Message.sender_id == current_user.id) |
        (models.Message.receiver_id == current_user.id)
    ).order_by(models.Message.timestamp.desc()).all()

    results = []
    seen_users = set()

    for msg in messages:
        if msg.sender_id == current_user.id:
            other_user = msg.receiver
        else:
            other_user = msg.sender

        if not other_user:
            continue

        # Prevent duplicate rows for the same conversation in the inbox list
        if other_user.id in seen_users:
            continue
        seen_users.add(other_user.id)

        results.append({
            "id": msg.id,
            "content": msg.content,
            "sender_id": msg.sender_id,
            "receiver_id": msg.receiver_id,
            "other_user_id": other_user.id,
            "other_user_name": other_user.username,
            # CRITICAL: Add both URL and the Version
            "other_user_avatar": other_user.avatar_url,
            "other_user_avatar_version": other_user.avatar_version or 1,
            "timestamp": msg.timestamp.isoformat()
        })
    return results

@app.get("/users/search")
def search_users(q: str, db: Session = Depends(get_db)):
    # Finds users whose names start with or contain the search string
    users = db.query(models.User).filter(
        models.User.username.ilike(f"%{q}%")
    ).limit(10).all()

    # ADD avatar_url to the dictionary below:
    return [
        {
            "id": u.id,
            "username": u.username,
            "avatar_url": u.avatar_url,  # <--- CRITICAL ADDITION
            "avatar_version": u.avatar_version or 1
        } for u in users
    ]

@app.post("/friends/request/{target_id}")
def send_friend_request(
    target_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.id == target_id:
        raise HTTPException(status_code=400, detail="Cannot add yourself")

    # Check if request already exists (in either direction)
    existing = db.query(models.Friendship).filter(
        or_(
            (models.Friendship.user_id == current_user.id) & (models.Friendship.friend_id == target_id),
            (models.Friendship.user_id == target_id) & (models.Friendship.friend_id == current_user.id)
        )
    ).first()

    if existing:
        if existing.status == 'accepted':
            raise HTTPException(status_code=400, detail="Already friends")
        raise HTTPException(status_code=400, detail="Request already pending")

    new_friendship = models.Friendship(
        user_id=current_user.id,
        friend_id=target_id,
        status='pending'
    )
    db.add(new_friendship)
    db.commit()
    return {"status": "sent"}

@app.post("/friends/accept/{request_id}")
def accept_friend_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Find the request where I AM THE RECEIVER (friend_id)
    friendship = db.query(models.Friendship).filter(
        models.Friendship.id == request_id,
        models.Friendship.friend_id == current_user.id,
        models.Friendship.status == 'pending'
    ).first()

    if not friendship:
        raise HTTPException(status_code=404, detail="Friend request not found")

    friendship.status = 'accepted'
    db.commit()
    return {"status": "accepted"}

@app.get("/friends/requests")
def get_friend_requests(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Get requests where I am the receiver (friend_id) and status is pending
    requests = db.query(models.Friendship).options(
        joinedload(models.Friendship.requester)
    ).filter(
        models.Friendship.friend_id == current_user.id,
        models.Friendship.status == 'pending'
    ).all()

    return [
        {"id": r.id, "username": r.requester.username, "user_id": r.user_id, "avatar_url": r.requester.avatar_url}
        for r in requests
    ]

@app.get("/friends/list")
def get_friends_list(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Find all accepted friendships where I am either the sender OR receiver
    friendships = db.query(models.Friendship).filter(
        (models.Friendship.user_id == current_user.id) | (models.Friendship.friend_id == current_user.id),
        models.Friendship.status == 'accepted'
    ).all()

    friends = []
    for f in friendships:
        # If I sent it, the friend is the receiver. If I received it, friend is sender.
        if f.user_id == current_user.id:
            # I sent it, so fetch receiver info
            friend_user = db.query(models.User).filter(models.User.id == f.friend_id).first()
        else:
            # I received it, so fetch sender info
            friend_user = db.query(models.User).filter(models.User.id == f.user_id).first()

        if friend_user:
            friends.append({"id": friend_user.id, "username": friend_user.username, "avatar_url": friend_user.avatar_url})

    return friends

@app.get("/friends/activity")
def get_friends_activity(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. Get List of Friend IDs (same as before)
    friendships = db.query(models.Friendship).filter(
        (models.Friendship.user_id == current_user.id) | (models.Friendship.friend_id == current_user.id),
        models.Friendship.status == 'accepted'
    ).all()

    friend_ids = []
    for f in friendships:
        friend_ids.append(f.friend_id if f.user_id == current_user.id else f.user_id)

    if not friend_ids:
        return []

    # 2. FIXED QUERY: Use .in_(friend_ids) instead of (...)
    activities = db.query(models.Like).options(
        joinedload(models.Like.user),
        joinedload(models.Like.post)
    ).filter(
        models.Like.user_id.in_(friend_ids)  # <--- FIX IS HERE
    ).order_by(models.Like.created_at.desc()).limit(20).all()

    results = []
    for act in activities:
        results.append({
            "username": act.user.username,
            "avatar_url": act.user.avatar_url,  # <--- ADD THIS
            "action": "liked" if act.vote_type == 1 else "disliked",
            "post_id": act.post.id if act.post else None, # Helpful for navigation
            "post_title": act.post.headline if act.post else "a post",
            "timestamp": act.created_at
        })

    return results

@app.post("/users/me/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    upload_dir = "static/avatars"
    os.makedirs(upload_dir, exist_ok=True)

    # 1. CLEANUP: Delete old files for this user to save space
    # Look for any file starting with "user_{id}." regardless of extension (jpg, png, etc.)
    search_pattern = os.path.join(upload_dir, f"user_{current_user.id}.*")
    old_files = glob.glob(search_pattern)

    for old_file in old_files:
        try:
            if os.path.exists(old_file):
                os.remove(old_file)
        except Exception as e:
            print(f"Error deleting old avatar: {e}")

    # 2. Create a unique filename for the NEW file
    extension = os.path.splitext(file.filename)[1].lower()
    if not extension: extension = ".jpg" # Fallback
    unique_filename = f"user_{current_user.id}{extension}"
    file_location = os.path.join(upload_dir, unique_filename)

    # 3. Save the new file
    try:
        # Reset file pointer to the beginning before copying
        await file.seek(0)
        with open(file_location, "wb+") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        print(f"File Save Error: {e}")
        raise HTTPException(status_code=500, detail="Could not save file to disk")

    # 4. Update Database and Increment Version for Cache Busting
    avatar_path = f"/static/avatars/{unique_filename}"
    current_user.avatar_url = avatar_path
    current_user.avatar_version = (current_user.avatar_version or 0) + 1

    db.commit()

    return {"avatar_url": avatar_path, "version": current_user.avatar_version}
