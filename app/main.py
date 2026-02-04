import asyncio
import feedparser
from fastapi import FastAPI, Depends, HTTPException, Response, status, Header, UploadFile, File, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func, or_, case, cast, Float
from typing import List, Optional
from datetime import datetime, timedelta, date
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
from time import mktime
import threading
import io
import re
from fastapi import File, UploadFile, Form # Add these
import uuid # Add this

import shutil
import os
import glob
import socket


# --- SECURITY CONFIGURATION ---
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_dev_key_only")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 week

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

# --- DB INIT ---
models.Base.metadata.create_all(bind=database.engine)

ENV = os.getenv("ENV", "development")

app = FastAPI(
    title="Skimsy API",
    # Hide docs in production by setting the URLs to None
    docs_url=None if ENV == "production" else "/docs",
    redoc_url=None if ENV == "production" else "/redoc",
    openapi_url=None if ENV == "production" else "/openapi.json",
    root_path="/api"
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

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

def extract_category_from_url(url: str) -> str:
    url = url.lower()
    if 'tech' in url or 'gadget' in url: return 'Tech'
    if 'politics' in url or 'election' in url: return 'Politics'
    if 'business' in url or 'money' in url: return 'Business'
    if 'world' in url: return 'World'
    if 'sport' in url: return 'Sports'
    return 'General'

def get_links_from_rss(rss_url: str) -> List[str]:
    """Works for almost any news site RSS feed"""
    feed = feedparser.parse(rss_url)
    # Extract just the URLs from the feed entries
    return [entry.link for entry in feed.entries]

socket.setdefaulttimeout(15)

# --- UPDATED SOURCE MAPPING ---
SOURCE_MAPPING = {
    # Major Global
    "cbc.ca": "CBC News",
    "bbc.co.uk": "BBC News",
    "bbc.com": "BBC News",
    "nytimes.com": "NY Times",
    "aljazeera.com": "Al Jazeera",
    "reuters.com": "Reuters",
    "apnews.com": "AP News",
    "cnn.com": "CNN",
    "foxnews.com": "Fox News",
    "nbcnews.com": "NBC News",
    "washingtonpost.com": "Washington Post",
    "guardian.co.uk": "The Guardian",
    "theguardian.com": "The Guardian",
    "usatoday.com": "USA Today",
    "dw.com": "Deutsche Welle",
    "france24.com": "France 24",

    # Tech & Science
    "theverge.com": "The Verge",
    "techcrunch.com": "TechCrunch",
    "wired.com": "Wired",
    "arstechnica.com": "Ars Technica",
    "engadget.com": "Engadget",
    "gizmodo.com": "Gizmodo",
    "mashable.com": "Mashable",
    "cnet.com": "CNET",
    "venturebeat.com": "VentureBeat",
    "sciencedaily.com": "Science Daily",
    "space.com": "Space.com",
    "nasa.gov": "NASA",
    "scientificamerican.com": "Scientific American",

    # Business
    "cnbc.com": "CNBC",
    "bloomberg.com": "Bloomberg",
    "forbes.com": "Forbes",
    "wsj.com": "Wall Street Journal",
    "businessinsider.com": "Business Insider",
    "ft.com": "Financial Times",
    "economist.com": "The Economist",
    "marketwatch.com": "MarketWatch",

    # Sports
    "espn.com": "ESPN",
    "bleacherreport.com": "Bleacher Report",
    "cbssports.com": "CBS Sports",
    "si.com": "Sports Illustrated",
    "nba.com": "NBA",
    "nfl.com": "NFL",
    "skysports.com": "Sky Sports",

    # Entertainment & Lifestyle
    "variety.com": "Variety",
    "hollywoodreporter.com": "Hollywood Reporter",
    "deadline.com": "Deadline",
    "rollingstone.com": "Rolling Stone",
    "billboard.com": "Billboard",
    "people.com": "People",
    "tmz.com": "TMZ",
    "ign.com": "IGN",
    "polygon.com": "Polygon",
    "kotaku.com": "Kotaku",
    "gamespot.com": "GameSpot",
    "eurogamer.net": "Eurogamer",

    # Crypto
    "coindesk.com": "CoinDesk",
    "cointelegraph.com": "CoinTelegraph",
    "decrypt.co": "Decrypt",
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

async def generic_news_scraper(rss_urls, limit_per_feed=15):
    while True:
        db = SessionLocal()
        try:
            print(f"--- Starting Generic Scrape ---")
            for rss_url in rss_urls:
                try:
                    # FIX: Identify source_name from the URL
                    source_name = "General News" # Fallback
                    for domain, name in SOURCE_MAPPING.items():
                        if domain in rss_url:
                            source_name = name
                            break

                    print(f"Fetching: {rss_url} ({source_name})")

                    try:
                        response = requests.get(rss_url, headers=HEADERS, timeout=10)
                        if response.status_code != 200:
                            print(f"Skipping {rss_url}: Status {response.status_code}")
                            continue
                        content = io.BytesIO(response.content)

                        # Pass the downloaded content to feedparser
                        loop = asyncio.get_event_loop()
                        feed = await loop.run_in_executor(None, lambda: feedparser.parse(content))

                    except requests.exceptions.Timeout:
                        print(f"Timeout skipping {rss_url}")
                        continue
                    except Exception as net_err:
                        print(f"Network error on {rss_url}: {net_err}")
                        continue

                    if feed.get('bozo'):
                        print(f"Warning: Malformed feed data from {rss_url}")

                    entries = feed.entries[:limit_per_feed]
                    for entry in entries:
                        link = entry.link

                        if db.query(models.Post).filter(models.Post.url == link).first():
                            continue

                        # FIX: mktime handling
                        pub_date = datetime.utcnow()
                        if hasattr(entry, 'published_parsed') and entry.published_parsed:
                            pub_date = datetime.fromtimestamp(mktime(entry.published_parsed))

                        # 2. Parse Data
                        scraped_data = auto_parse_news(link)
                        if not scraped_data:
                            continue

                        new_post = models.Post(
                            headline=scraped_data["headline"],
                            image_url=scraped_data.get("image_url"),
                            category=scraped_data["category"],
                            bullet_points=scraped_data["bullets"],
                            url=link,
                            source_url=link,
                            source_name=source_name,
                            created_at=pub_date
                        )

                        db.add(new_post)
                        db.commit()
                        print(f"Added: [{source_name}] {scraped_data['headline'][:40]}...")

                        await asyncio.sleep(1)

                except Exception as feed_err:
                    print(f"Failed to process feed {rss_url}: {feed_err}")
                    continue

        except Exception as e:
            print(f"Global Scraper Error: {e}")
        finally:
            db.close()

        print("--- Cycle Complete. Sleeping 30m ---")
        await asyncio.sleep(1800)

@app.on_event("startup")
async def startup_event():
    feeds = [
        # --- WORLD & MAJOR NEWS ---
        "http://feeds.bbci.co.uk/news/world/rss.xml",           # BBC World
        "https://www.aljazeera.com/xml/rss/all.xml",            # Al Jazeera
        "https://rss.nytimes.com/services/xml/rss/nyt/World.xml", # NYT World
        "https://www.cbc.ca/webfeed/rss/rss-world",             # CBC World
        "http://feeds.washingtonpost.com/rss/world",            # WaPo World
        "https://www.theguardian.com/world/rss",                # The Guardian
        "https://rss.dw.com/xml/rss-en-all",                    # Deutsche Welle
        "https://www.france24.com/en/rss",                      # France 24

        # --- POLITICS ---
        "http://rss.cnn.com/rss/cnn_allpolitics.rss",           # CNN Politics
        "https://www.politico.com/rss/politicopicks.xml",       # Politico
        "https://feeds.npr.org/1014/rss.xml",                   # NPR Politics
        "https://thehill.com/feed/",                            # The Hill

        # --- BUSINESS & FINANCE ---
        "https://search.cnbc.com/rs/search/view.xml?partnerId=2000&keywords=finance", # CNBC
        "https://feeds.npr.org/1006/rss.xml",                   # NPR Business
        "https://feeds.bloomberg.com/markets/news.rss",         # Bloomberg Markets
        "https://www.economist.com/business/rss.xml",           # The Economist
        "http://feeds.marketwatch.com/marketwatch/topstories/", # MarketWatch

        # --- TECH & FUTURE ---
        "https://www.theverge.com/rss/index.xml",               # The Verge
        "https://techcrunch.com/feed/",                         # TechCrunch
        "https://www.wired.com/feed/rss",                       # Wired
        "https://arstechnica.com/feed/",                        # Ars Technica
        "https://www.engadget.com/rss.xml",                     # Engadget
        "https://gizmodo.com/rss",                              # Gizmodo
        "https://mashable.com/feeds/rss/tech",                  # Mashable Tech
        "https://venturebeat.com/feed/",                        # VentureBeat

        # --- GAMING ---
        "https://www.ign.com/rss/articles.xml",                 # IGN
        "https://www.polygon.com/rss/index.xml",                # Polygon
        "https://kotaku.com/rss",                               # Kotaku
        "https://www.gamespot.com/feeds/news/",                 # GameSpot
        "https://www.eurogamer.net/?format=rss",                # Eurogamer

        # --- SPORTS ---
        "https://www.espn.com/espn/rss/news",                   # ESPN Top News
        "https://api.foxsports.com/v1/rss?partnerKey=zBaFxRyGKCfxBagJG9b8pqLyndmvo7UU", # Fox Sports
        "https://sports.yahoo.com/rss/",                        # Yahoo Sports
        "https://www.cbssports.com/rss/headlines/",             # CBS Sports

        # --- ENTERTAINMENT & CULTURE ---
        "https://www.variety.com/feed/",                        # Variety
        "https://www.hollywoodreporter.com/feed/",              # Hollywood Reporter
        "https://deadline.com/feed/",                           # Deadline
        "https://www.rollingstone.com/feed/",                   # Rolling Stone
        "https://www.billboard.com/feed/",                      # Billboard Music
        "https://people.com/feed/",                             # People

        # --- SCIENCE & SPACE ---
        "https://www.sciencedaily.com/rss/all.xml",             # Science Daily
        "https://www.nasa.gov/rss/dyn/breaking_news.rss",       # NASA
        "https://www.scientificamerican.com/feed.xml",          # Scientific American
        "https://www.space.com/feeds/all",                      # Space.com

        # --- CRYPTO ---
        "https://www.coindesk.com/arc/outboundfeeds/rss/",      # CoinDesk
        "https://cointelegraph.com/rss",                        # CoinTelegraph
        "https://decrypt.co/feed"                               # Decrypt
    ]

    # Define a helper to run the async function in a new thread's loop
    def run_scraper():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(generic_news_scraper(feeds, limit_per_feed=15))

    # Start the thread
    #scraper_thread = threading.Thread(target=run_scraper, daemon=True)
    #scraper_thread.start()

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
    sort: str = "newest",
    category: Optional[str] = None,
    time: str = "all",
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
):
    # 1. Start Query
    query = db.query(models.Post).options(
        joinedload(models.Post.comments).joinedload(models.Comment.author)
    )

    # 2. Filters (Category & Time)
    if category and category.strip() != "" and category.lower() != "all":
        query = query.filter(models.Post.category.ilike(category))

    if time != "all":
        now = datetime.utcnow()
        start_date = None
        if time == "24h":
            start_date = now - timedelta(hours=24)
        elif time == "week":
            start_date = now - timedelta(weeks=1)
        elif time == "month":
            start_date = now - timedelta(days=30)

        if start_date:
            query = query.filter(models.Post.created_at >= start_date)

    # 3. Apply Sorting
    if sort in ["hot", "top", "controversial", "engagement"]:
        # Subquery: Calculate Net Score (Likes - Dislikes) and Total Votes
        vote_stats = db.query(
            models.Like.post_id,
            func.sum(models.Like.vote_type).label('net_score'),
            func.count(models.Like.id).label('total_votes')
        ).group_by(models.Like.post_id).subquery()

        # Join stats to main query
        query = query.outerjoin(vote_stats, models.Post.id == vote_stats.c.post_id)

        # Helper variables for SQL logic
        net_score = func.coalesce(vote_stats.c.net_score, 0)
        total_votes = func.coalesce(vote_stats.c.total_votes, 0)

        if sort == "hot" or sort == "engagement":
            # --- REDDIT HOT ALGORITHM ---
            # 1. Order Magnitude: log10(max(|score|, 1))
            order_magnitude = func.log(10, func.greatest(func.abs(net_score), 1))

            # 2. Sign: 1 if positive, -1 if negative.
            # We treat 0 as 1 so new posts (score 0) don't get zeroed out by time.
            sign = case((net_score < 0, -1), else_=1)

            # 3. Seconds: Time since Reddit Epoch (Dec 8 2005)
            # Using 1134028003 as constant
            seconds = func.extract('epoch', models.Post.created_at) - 1134028003

            # 4. Formula: val + (sign * seconds / 45000)
            hot_score = cast(order_magnitude, Float) + (cast(sign, Float) * cast(seconds, Float) / 45000.0)

            query = query.order_by(desc(hot_score))

        elif sort == "top":
            # TOP: Highest Net Score
            query = query.order_by(desc(net_score), desc(models.Post.created_at))

        elif sort == "controversial":
            # CONTROVERSIAL: High Total Votes but Net Score close to 0
            # Logic: Order by Total Votes DESC, then Absolute Net Score ASC
            query = query.order_by(desc(total_votes), func.abs(net_score))

    else:
        # Default: Newest first
        query = query.order_by(desc(models.Post.created_at))

    # 4. Pagination
    query = query.offset(skip).limit(limit)
    posts = query.all()

    current_user_id = current_user.id if current_user else None

    # 5. Populate local counts (Python side for accuracy on returned items)
    for post in posts:
        post.like_count = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.vote_type == 1).count()
        post.dislike_count = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.vote_type == -1).count()

        post.user_vote = 0
        if current_user:
            user_vote_obj = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.user_id == current_user.id).first()
            if user_vote_obj:
                post.user_vote = user_vote_obj.vote_type

        populate_comment_scores(post.comments, db, current_user_id)

    return posts
    # 1. Start Query
    query = db.query(models.Post).options(
        joinedload(models.Post.comments).joinedload(models.Comment.author)
    )

    # 2. Filters (Category & Time)
    if category and category.strip() != "" and category.lower() != "all":
        query = query.filter(models.Post.category.ilike(category))

    if time != "all":
        now = datetime.utcnow()
        start_date = None
        if time == "24h":
            start_date = now - timedelta(hours=24)
        elif time == "week":
            start_date = now - timedelta(weeks=1)
        elif time == "month":
            start_date = now - timedelta(days=30)

        if start_date:
            query = query.filter(models.Post.created_at >= start_date)

    # 3. Apply Sorting
    if sort in ["engagement", "liked"]:
        # Calculate TOTAL engagement (Likes + Dislikes)
        engagement_counts = db.query(
            models.Like.post_id,
            func.count(models.Like.id).label('total_engagement')
        ).group_by(models.Like.post_id).subquery()

        # Join the engagement subquery
        query = query.outerjoin(engagement_counts, models.Post.id == engagement_counts.c.post_id)

        # Order by total engagement first, then by date
        query = query.order_by(
            desc(func.coalesce(engagement_counts.c.total_engagement, 0)),
            desc(models.Post.created_at)
        )
    else:
        # Default: Newest first
        query = query.order_by(desc(models.Post.created_at))

    # 4. Execute Query
    posts = query.all()

    # Define user ID once to use inside the loop
    current_user_id = current_user.id if current_user else None

    # --- CRITICAL FIX: POPULATE COUNTS ---
    for post in posts:
        # Calculate Post Likes (Existing)
        post.like_count = db.query(models.Like).filter(
            models.Like.post_id == post.id,
            models.Like.vote_type == 1
        ).count()

        # Calculate Post Dislikes (Existing)
        post.dislike_count = db.query(models.Like).filter(
            models.Like.post_id == post.id,
            models.Like.vote_type == -1
        ).count()

        # Calculate Post User Vote (Existing)
        post.user_vote = 0
        if current_user:
            user_vote_obj = db.query(models.Like).filter(
                models.Like.post_id == post.id,
                models.Like.user_id == current_user.id
            ).first()
            if user_vote_obj:
                post.user_vote = user_vote_obj.vote_type

        # --- NEW: POPULATE SCORES FOR COMMENTS IN THE FEED ---
        # This was missing! It ensures comments on the Home screen have likes.
        populate_comment_scores(post.comments, db, current_user_id)

    return posts

@app.get("/news/search")
def search_news(
    q: Optional[str] = None,
    sort: str = "relevance",
    time: str = "all",
    skip: int = 0,   # <--- Added
    limit: int = 10, # <--- Added (Default 10)
    db: Session = Depends(get_db)
):
    query = db.query(models.Post)

    if q:
        query = query.filter(models.Post.headline.ilike(f"%{q}%"))

    # Time Filter
    now = datetime.utcnow()
    if time == "hour":
        query = query.filter(models.Post.created_at >= now - timedelta(hours=1))
    elif time == "day":
        query = query.filter(models.Post.created_at >= now - timedelta(hours=24))
    elif time == "week":
        query = query.filter(models.Post.created_at >= now - timedelta(weeks=1))
    elif time == "month":
        query = query.filter(models.Post.created_at >= now - timedelta(days=30))
    elif time == "year":
        query = query.filter(models.Post.created_at >= now - timedelta(days=365))

    # Sort Logic
    if sort == "new":
        query = query.order_by(desc(models.Post.created_at))
    elif sort == "top":
        subquery = db.query(models.Like.post_id, func.count(models.Like.id).label('like_count')).filter(models.Like.vote_type == 1).group_by(models.Like.post_id).subquery()
        query = query.outerjoin(subquery, models.Post.id == subquery.c.post_id).order_by(desc(func.coalesce(subquery.c.like_count, 0)))
    elif sort == "comments":
        subquery = db.query(models.Comment.post_id, func.count(models.Comment.id).label('comment_count')).group_by(models.Comment.post_id).subquery()
        query = query.outerjoin(subquery, models.Post.id == subquery.c.post_id).order_by(desc(func.coalesce(subquery.c.comment_count, 0)))
    elif sort == "hot":
         query = query.outerjoin(models.Like).group_by(models.Post.id).order_by(desc(func.count(models.Like.id)))
    else:
        query = query.order_by(desc(models.Post.created_at))

    # PAGINATION APPLIED HERE
    return query.offset(skip).limit(limit).all()

@app.get("/comments/search")
def search_comments(
    q: str,
    sort: str = "relevance",
    skip: int = 0,   # <--- Added
    limit: int = 10, # <--- Added
    db: Session = Depends(get_db)
):
    query = db.query(models.Comment).join(models.Post).options(
        joinedload(models.Comment.author),
        joinedload(models.Comment.post)
    )

    if q:
        query = query.filter(models.Comment.content.ilike(f"%{q}%"))

    if sort == "new":
        query = query.order_by(desc(models.Comment.timestamp))
    elif sort == "top":
        subquery = db.query(models.CommentLike.comment_id, func.sum(models.CommentLike.vote_type).label('score')).group_by(models.CommentLike.comment_id).subquery()
        query = query.outerjoin(subquery, models.Comment.id == subquery.c.comment_id).order_by(desc(func.coalesce(subquery.c.score, 0)))
    else:
        query = query.order_by(desc(models.Comment.timestamp))

    # PAGINATION APPLIED HERE
    results = query.offset(skip).limit(limit).all()

    # Formatting logic remains the same...
    data = []
    for c in results:
        data.append({
            "id": c.id,
            "content": c.content,
            "timestamp": c.timestamp,
            "username": c.author.username if c.author else "User",
            "avatar_url": c.author.avatar_url if c.author else None,
            "post_id": c.post_id,
            "post_headline": c.post.headline if c.post else "Unknown Post",
            "score": 0
        })
    return data

# --- SOCIAL ENDPOINTS ---

@app.post("/comments", response_model=schemas.Comment)
async def create_comment(
    content: str = Form(...),
    post_id: int = Form(...),
    parent_id: Optional[int] = Form(None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. Handle Image Upload (Keep existing logic)
    image_path = None
    if image:
        upload_dir = "app/static/comment_images"
        os.makedirs(upload_dir, exist_ok=True)
        ext = os.path.splitext(image.filename)[1]
        filename = f"{uuid.uuid4()}{ext}"
        file_location = os.path.join(upload_dir, filename)
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        image_path = f"/static/comment_images/{filename}"

    # 2. Create Comment
    new_comment = models.Comment(
        content=content,
        post_id=post_id,
        parent_id=parent_id,
        user_id=current_user.id,
        image_url=image_path
    )
    db.add(new_comment)
    db.flush() # Flush to generate new_comment.id without committing yet

    # --- FIX START: AUTO-UPVOTE ---
    # Automatically add a "Like" (vote_type=1) for the author
    auto_like = models.CommentLike(
        user_id=current_user.id,
        comment_id=new_comment.id,
        vote_type=1
    )
    db.add(auto_like)
    # --- FIX END ---

    # 3. DETECT MENTIONS (Keep existing logic)
    mentioned_usernames = re.findall(r"@(\w+)", content)
    unique_mentions = set(mentioned_usernames)

    for username in unique_mentions:
        target_user = db.query(models.User).filter(
            models.User.username.ilike(username)
        ).first()

        if target_user and target_user.id != current_user.id:
            notification = models.Notification(
                user_id=target_user.id,
                sender_id=current_user.id,
                post_id=post_id,
                comment_id=new_comment.id,
                type="mention",
                timestamp=datetime.utcnow()
            )
            db.add(notification)

    db.commit()

    # 4. Return the result
    db_comment = db.query(models.Comment).options(
        joinedload(models.Comment.author)
    ).filter(models.Comment.id == new_comment.id).first()

    # Manually set the score/vote fields for the immediate response
    # Since we just created it and liked it, score is 1 and vote is 1.
    db_comment.score = 1
    db_comment.user_vote = 1

    return db_comment

@app.post("/comments/{comment_id}/vote", response_model=schemas.CommentVoteResponse)
def vote_comment(
    comment_id: int,
    vote_type: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. Check if comment exists
    comment = db.query(models.Comment).filter(models.Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # 2. Check for existing vote
    existing_vote = db.query(models.CommentLike).filter(
        models.CommentLike.comment_id == comment_id,
        models.CommentLike.user_id == current_user.id
    ).first()

    final_user_vote = vote_type

    if existing_vote:
        if existing_vote.vote_type == vote_type:
            # Toggle off (remove vote if clicking same button)
            db.delete(existing_vote)
            final_user_vote = 0
        else:
            # Change vote (Like -> Dislike or vice versa)
            existing_vote.vote_type = vote_type
    else:
        # Create new vote
        new_vote = models.CommentLike(
            user_id=current_user.id,
            comment_id=comment_id,
            vote_type=vote_type
        )
        db.add(new_vote)

    db.commit()

    # 3. Calculate new score to return immediately
    likes = db.query(models.CommentLike).filter(
        models.CommentLike.comment_id == comment_id,
        models.CommentLike.vote_type == 1
    ).count()

    dislikes = db.query(models.CommentLike).filter(
        models.CommentLike.comment_id == comment_id,
        models.CommentLike.vote_type == -1
    ).count()

    return {"score": likes - dislikes, "user_vote": final_user_vote}

@app.delete("/comments/{comment_id}")
def delete_comment(
    comment_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. Find the comment
    comment = db.query(models.Comment).filter(models.Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # 2. Check ownership
    if comment.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this comment")

    # 3. Check for replies (children)
    # We look for any comment whose parent_id matches this comment's ID
    has_replies = db.query(models.Comment).filter(models.Comment.parent_id == comment_id).count() > 0

    if has_replies:
        # SOFT DELETE: Keep structure, hide content
        comment.content = "[deleted]"
        comment.user_id = None # Remove link to user
        # comment.is_deleted = True # Optional: If you added a flag column
        db.commit()
        return {"status": "soft_deleted", "id": comment_id}
    else:
        # HARD DELETE: No children, safe to remove completely
        db.delete(comment)
        db.commit()
        return {"status": "hard_deleted", "id": comment_id}

@app.put("/comments/{comment_id}")
def update_comment(
    comment_id: int,
    payload: dict = Body(...), # Expects {"content": "New text"}
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    comment = db.query(models.Comment).filter(models.Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Check ownership
    if comment.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to edit this comment")

    new_content = payload.get("content")
    if not new_content or not new_content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty")

    comment.content = new_content
    comment.is_edited = True # Set the flag
    db.commit()

    return comment

@app.post("/posts/{post_id}/vote", response_model=schemas.VoteResponse)
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

    # Track what the final state will be for the frontend
    final_user_vote = vote_type

    if existing_vote:
        if existing_vote.vote_type == vote_type:
            # User clicked the same button again -> Remove the vote
            db.delete(existing_vote)
            final_user_vote = 0
        else:
            # User changed from like to dislike or vice versa
            existing_vote.vote_type = vote_type
    else:
        new_vote = models.Like(user_id=current_user.id, post_id=post_id, vote_type=vote_type)
        db.add(new_vote)

    db.commit()

    # Get fresh counts
    likes = db.query(models.Like).filter(models.Like.post_id == post_id, models.Like.vote_type == 1).count()
    dislikes = db.query(models.Like).filter(models.Like.post_id == post_id, models.Like.vote_type == -1).count()

    return {
        "like_count": likes,
        "dislike_count": dislikes,
        "user_vote": final_user_vote
    }

def populate_comment_scores(comments, db, current_user_id=None):
    for comment in comments:
        # 1. Get raw counts
        likes = db.query(models.CommentLike).filter(
            models.CommentLike.comment_id == comment.id,
            models.CommentLike.vote_type == 1
        ).count()

        dislikes = db.query(models.CommentLike).filter(
            models.CommentLike.comment_id == comment.id,
            models.CommentLike.vote_type == -1
        ).count()

        # 2. Set the 'score' attribute (net sum)
        comment.score = likes - dislikes

        # 3. Check user status
        comment.user_vote = 0
        if current_user_id:
            user_vote_obj = db.query(models.CommentLike).filter(
                models.CommentLike.comment_id == comment.id,
                models.CommentLike.user_id == current_user_id
            ).first()
            if user_vote_obj:
                comment.user_vote = user_vote_obj.vote_type

        # 4. Recursively process replies if they exist
        if hasattr(comment, "replies") and comment.replies:
             populate_comment_scores(comment.replies, db, current_user_id)

@app.get("/posts/{post_id}", response_model=schemas.Post)
def get_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
):
    # 1. Fetch post
    post = db.query(models.Post).options(
        joinedload(models.Post.comments).joinedload(models.Comment.author)
    ).filter(models.Post.id == post_id).first()

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # 2. Update views
    post.views = (post.views or 0) + 1
    db.commit()
    db.refresh(post)

    # 3. Post Social Counts
    post.like_count = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.vote_type == 1).count()
    post.dislike_count = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.vote_type == -1).count()

    post.user_vote = 0
    current_user_id = current_user.id if current_user else None

    if current_user:
        vote = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.user_id == current_user.id).first()
        if vote:
            post.user_vote = vote.vote_type

    # 4. NEW: Populate Comment Scores
    # We only process top-level comments here to avoid double counting if recursion is handled by SQLAlchemy
    # But strictly speaking, the `post.comments` list usually contains ALL comments flatly if not configured as a tree.
    # To be safe, we iterate whatever `post.comments` returns.
    populate_comment_scores(post.comments, db, current_user_id)

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
    messages = db.query(models.Message).filter(
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

@app.post("/users/checkin")
def daily_checkin(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    today = date.today()

    # 1. Check if already checked in today
    if current_user.last_checkin == today:
        return {
            "status": "already_checked_in",
            "count": current_user.checkin_count,
            "new_checkin": False
        }

    # 2. Update User
    current_user.last_checkin = today
    current_user.checkin_count = (current_user.checkin_count or 0) + 1

    db.commit()

    return {
        "status": "success",
        "count": current_user.checkin_count,
        "new_checkin": True
    }

@app.get("/users/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "avatar_url": current_user.avatar_url,
        "avatar_version": current_user.avatar_version or 1,
        "checkin_count": current_user.checkin_count or 0 # Key for cache busting
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
    results = []

    # 1. FETCH MENTIONS (New)
    # "Who mentioned ME?"
    mentions = db.query(models.Notification).options(
        joinedload(models.Notification.sender),
        joinedload(models.Notification.post)
    ).filter(
        models.Notification.user_id == current_user.id,
        models.Notification.type == "mention"
    ).order_by(models.Notification.timestamp.desc()).limit(20).all()

    for notif in mentions:
        results.append({
            "username": notif.sender.username,
            "avatar_url": notif.sender.avatar_url,
            "avatar_version": notif.sender.avatar_version or 1,
            "action": "mentioned you in", # Special string we will check in frontend
            "post_id": notif.post_id,
            "post_title": notif.post.headline if notif.post else "a comment",
            "timestamp": notif.timestamp
        })

    # 2. FETCH FRIEND ACTIVITY (Existing Logic)
    # "What did my friends do?"
    friendships = db.query(models.Friendship).filter(
        (models.Friendship.user_id == current_user.id) | (models.Friendship.friend_id == current_user.id),
        models.Friendship.status == 'accepted'
    ).all()

    friend_ids = []
    for f in friendships:
        friend_ids.append(f.friend_id if f.user_id == current_user.id else f.user_id)

    if friend_ids:
        activities = db.query(models.Like).options(
            joinedload(models.Like.user),
            joinedload(models.Like.post)
        ).filter(
            models.Like.user_id.in_(friend_ids)
        ).order_by(models.Like.created_at.desc()).limit(20).all()

        for act in activities:
            results.append({
                "username": act.user.username,
                "avatar_url": act.user.avatar_url,
                "avatar_version": act.user.avatar_version or 1,
                "action": "liked" if act.vote_type == 1 else "disliked",
                "post_id": act.post.id if act.post else None,
                "post_title": act.post.headline if act.post else "a post",
                "timestamp": act.created_at
            })

    # 3. Sort combined list by date
    results.sort(key=lambda x: x['timestamp'], reverse=True)

    return results

@app.get("/users/{user_id}")
def get_user_profile(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user.id,
        "username": user.username,
        # We exclude email for privacy since this is a public profile view
        "avatar_url": user.avatar_url,
        "avatar_version": user.avatar_version or 1,
        "checkin_count": user.checkin_count or 0
    }

@app.post("/users/me/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    upload_dir = "app/static/avatars"
    os.makedirs(upload_dir, exist_ok=True)

    # 1. CLEANUP: (Keep this part exactly as it is)
    search_pattern = os.path.join(upload_dir, f"user_{current_user.id}.*")
    old_files = glob.glob(search_pattern)

    for old_file in old_files:
        try:
            if os.path.exists(old_file):
                os.remove(old_file)
        except Exception as e:
            print(f"Error deleting old avatar: {e}")

    # 2. Filename Logic (Keep this)
    extension = os.path.splitext(file.filename)[1].lower()
    if not extension: extension = ".jpg"
    unique_filename = f"user_{current_user.id}{extension}"
    file_location = os.path.join(upload_dir, unique_filename)

    # 3. SAVE THE NEW FILE (Updated Fix)
    try:
        # FIX: Use await file.read() instead of mixing seek/shutil
        # This ensures the file is fully received before writing
        contents = await file.read()

        with open(file_location, "wb") as buffer:
            buffer.write(contents)

    except Exception as e:
        print(f"File Save Error: {e}")
        raise HTTPException(status_code=500, detail="Could not save file to disk")

    # 4. Update Database (Keep this)
    avatar_path = f"/static/avatars/{unique_filename}"
    current_user.avatar_url = avatar_path
    current_user.avatar_version = (current_user.avatar_version or 0) + 1

    db.commit()

    return {"avatar_url": avatar_path, "version": current_user.avatar_version}
