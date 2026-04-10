import asyncio
import feedparser
from fastapi import FastAPI, Depends, HTTPException, Response, status, Header, UploadFile, File, Body, Request
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func, or_, case, cast, Float, text
from sqlalchemy.exc import IntegrityError
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
from PIL import Image as PilImage

MAX_IMAGE_DIMENSION = 1080

def save_image_resized(data: bytes, path: str):
    """Resize to fit within 1080px on longest side, save as JPEG. Same as Instagram/Reddit."""
    img = PilImage.open(io.BytesIO(data))
    img = img.convert("RGB")
    img.thumbnail((MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION), PilImage.LANCZOS)
    img.save(path, "JPEG", quality=85, optimize=True)



# --- SECURITY CONFIGURATION ---
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_dev_key_only")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 week

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

# --- DB INIT ---
models.Base.metadata.create_all(bind=database.engine)

# --- RUNTIME MIGRATIONS (idempotent) ---
def _run_migrations():
    with database.engine.connect() as conn:
        for stmt in [
            "ALTER TABLE user_posts ADD COLUMN IF NOT EXISTS link_url VARCHAR",
            "ALTER TABLE user_posts ADD COLUMN IF NOT EXISTS link_title VARCHAR",
            "ALTER TABLE user_posts ADD COLUMN IF NOT EXISTS link_image VARCHAR",
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS image_url VARCHAR",
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_id INTEGER REFERENCES messages(id)",
            "ALTER TABLE messages ALTER COLUMN content DROP NOT NULL",
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS keywords JSONB DEFAULT '[]'",
        ]:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS message_reactions (
                id SERIAL PRIMARY KEY,
                message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id),
                emoji VARCHAR,
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(message_id, user_id)
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS user_interests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                keyword VARCHAR(100) NOT NULL,
                score FLOAT NOT NULL DEFAULT 0.0,
                updated_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(user_id, keyword)
            )
        """))
        conn.commit()

_run_migrations()

ENV = os.getenv("ENV", "development")

# In-memory presence state (no DB migration needed)
from datetime import datetime as _dt
_typing_state: dict = {}   # {typer_id: {recipient_id: datetime}}
_last_seen: dict = {}      # {user_id: datetime}

app = FastAPI(
    title="Skimsy API",
    # Only set root_path if we are in production
    root_path="/api" if ENV == "production" else "",

    # Hide docs in production (optional, but good practice)
    docs_url=None if ENV == "production" else "/docs",
    redoc_url=None if ENV == "production" else "/redoc",
    openapi_url=None if ENV == "production" else "/openapi.json",
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

# ---------- OG PREVIEW HELPERS ----------
_BOT_UA = re.compile(
    r'(facebookexternalhit|twitterbot|linkedinbot|whatsapp|slack|kakao'
    r'|telegram|discordbot|googlebot|bingbot|applebot|crawler|spider|preview|bot)',
    re.IGNORECASE,
)

def _is_bot(ua: str) -> bool:
    return bool(_BOT_UA.search(ua))

def _og_html(title: str, description: str, image_url: str | None, page_url: str) -> str:
    t = (title or 'Skimsy').replace('"', '&quot;')[:120]
    d = (description or '').replace('"', '&quot;')[:200]
    img = f'<meta property="og:image" content="{image_url}">\n    <meta name="twitter:image" content="{image_url}">' if image_url else ''
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{t} — Skimsy</title>
<meta property="og:site_name" content="Skimsy">
<meta property="og:type" content="article">
<meta property="og:title" content="{t}">
<meta property="og:description" content="{d}">
<meta property="og:url" content="{page_url}">
{img}
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{t}">
<meta name="twitter:description" content="{d}">
</head>
<body></body>
</html>"""

def _spa_html() -> str:
    try:
        with open("/code/dist/index.html") as f:
            return f.read()
    except FileNotFoundError:
        return '<html><body><script>window.location="/"</script></body></html>'

@app.get("/news/{news_id}", response_class=HTMLResponse)
def og_news(news_id: int, request: Request, db: Session = Depends(get_db)):
    post = db.query(models.Post).filter(models.Post.id == news_id).first()
    if not post:
        raise HTTPException(status_code=404)
    if not _is_bot(request.headers.get("user-agent", "")):
        return HTMLResponse(_spa_html())
    return HTMLResponse(_og_html(
        title=post.headline,
        description=getattr(post, 'summary', None) or post.source_name or '',
        image_url=post.image_url,
        page_url=str(request.url),
    ))

@app.get("/post/{post_id}", response_class=HTMLResponse)
def og_post(post_id: int, request: Request, db: Session = Depends(get_db)):
    post = db.query(models.UserPost).filter(models.UserPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404)
    if not _is_bot(request.headers.get("user-agent", "")):
        return HTMLResponse(_spa_html())
    author = post.author.username if post.author else 'Someone'
    # Prefer link preview data when the post is a news share
    title = post.link_title or f"{author} on Skimsy"
    description = post.content or ''
    image_url = post.link_image or post.image_url
    return HTMLResponse(_og_html(
        title=title,
        description=description,
        image_url=image_url,
        page_url=str(request.url),
    ))

origins = [
    "http://localhost:8081",
    "https://skimsy.app",
    "https://skimsy.app/",      # Add this
    "https://www.skimsy.app",
    "https://www.skimsy.app/",   # Add this
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
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
                            keywords=scraped_data.get("keywords", []),
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

        print("--- Cycle Complete. Sleeping 5m ---")
        await asyncio.sleep(300)

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

    # Start the scraper thread
    scraper_thread = threading.Thread(target=run_scraper, daemon=True)
    scraper_thread.start()

# --- AUTH ENDPOINTS ---

@app.post("/register", response_model=schemas.User)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="That email is already registered. Try logging in instead.")
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="That username is already taken. Please choose a different one.")

    new_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=get_password_hash(user.password)
    )
    db.add(new_user)
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        err = str(e.orig).lower()
        if "username" in err:
            raise HTTPException(status_code=400, detail="That username is already taken. Please choose a different one.")
        if "email" in err:
            raise HTTPException(status_code=400, detail="That email is already registered. Try logging in instead.")
        raise HTTPException(status_code=400, detail="Account could not be created. Please try again.")
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

@app.get("/feed/foryou", response_model=List[schemas.Post])
def get_for_you_feed(
    skip: int = 0,
    limit: int = 10,
    category: Optional[str] = None,
    exclude_ids: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
):
    """Personalised feed: hot-ranked candidates re-scored by keyword affinity."""
    CANDIDATES = 200

    # --- Build hot-ranked candidate pool (last 30 days) ---
    vote_stats = db.query(
        models.Like.post_id,
        func.sum(models.Like.vote_type).label('net_score'),
    ).group_by(models.Like.post_id).subquery()

    base_query = db.query(models.Post).options(
        joinedload(models.Post.comments).joinedload(models.Comment.author)
    ).filter(
        models.Post.created_at >= datetime.utcnow() - timedelta(days=30)
    ).outerjoin(vote_stats, models.Post.id == vote_stats.c.post_id)

    if category and category.strip() and category.lower() != "all":
        base_query = base_query.filter(models.Post.category.ilike(category))

    net_score = func.coalesce(vote_stats.c.net_score, 0)
    sign = case((net_score < 0, -1), else_=1)
    seconds = func.extract('epoch', models.Post.created_at) - 1134028003
    order_magnitude = func.log(10, func.greatest(func.abs(net_score), 1))
    hot_score_expr = cast(order_magnitude, Float) + (cast(sign, Float) * cast(seconds, Float) / 45000.0)

    candidates = base_query.order_by(desc(hot_score_expr)).limit(CANDIDATES).all()

    # --- Re-rank by keyword affinity if user has interests ---
    interest_dict: dict = {}
    if current_user:
        rows = db.query(models.UserInterest).filter(
            models.UserInterest.user_id == current_user.id
        ).order_by(desc(models.UserInterest.score)).limit(40).all()
        interest_dict = {r.keyword: r.score for r in rows}

    def affinity(post):
        kws = post.keywords or []
        if not kws or not interest_dict:
            return 0.0
        return sum(interest_dict.get(k.lower(), 0.0) for k in kws) / len(kws)

    excluded = set(int(x) for x in exclude_ids.split(',') if x.strip().isdigit()) if exclude_ids else set()
    if excluded:
        candidates = [p for p in candidates if p.id not in excluded]

    scored = [(len(candidates) - i + affinity(p) * 25, p) for i, p in enumerate(candidates)]
    scored.sort(key=lambda x: x[0], reverse=True)
    page = [p for _, p in scored][skip: skip + limit]

    current_user_id = current_user.id if current_user else None
    for post in page:
        post.like_count = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.vote_type == 1).count()
        post.dislike_count = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.vote_type == -1).count()
        post.user_vote = 0
        if current_user_id:
            uv = db.query(models.Like).filter(models.Like.post_id == post.id, models.Like.user_id == current_user_id).first()
            if uv:
                post.user_vote = uv.vote_type
        populate_comment_scores(post.comments, db, current_user_id)
    return page


@app.post("/feed/engagement")
def record_engagement(
    post_id: int,
    engagement_type: str = "view",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Called by client when user dwells on a card (view) or opens the article (open)."""
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if not post or not post.keywords:
        return {"ok": True}
    delta = {"view": 1.0, "open": 2.0}.get(engagement_type, 0.0)
    if delta > 0:
        update_user_interests(db, current_user.id, post.keywords, delta)
        db.commit()
    return {"ok": True}


@app.get("/news/search")
def search_news(
    q: Optional[str] = None,
    sort: str = "relevance",
    time: str = "all",
    category: Optional[str] = None,
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    query = db.query(models.Post)

    if q:
        query = query.filter(models.Post.headline.ilike(f"%{q}%"))

    if category and category.strip() and category.lower() != "all":
        query = query.filter(models.Post.category.ilike(category))

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

# DEPRECATED: Old /comments endpoint removed. See updated version at end of file.

@app.post("/comments/{comment_id}/vote"
, response_model=schemas.CommentVoteResponse)
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

    # Update user interests based on vote
    voted_post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if voted_post and voted_post.keywords:
        if final_user_vote == 1:
            update_user_interests(db, current_user.id, voted_post.keywords, 3.0)
        elif final_user_vote == -1:
            update_user_interests(db, current_user.id, voted_post.keywords, -1.0)

    db.commit()

    # Get fresh counts
    likes = db.query(models.Like).filter(models.Like.post_id == post_id, models.Like.vote_type == 1).count()
    dislikes = db.query(models.Like).filter(models.Like.post_id == post_id, models.Like.vote_type == -1).count()

    return {
        "like_count": likes,
        "dislike_count": dislikes,
        "user_vote": final_user_vote
    }

def update_user_interests(db, user_id: int, keywords: list, delta: float):
    """Upsert keyword interest scores for a user. Does NOT commit — caller must commit."""
    if not keywords or not user_id:
        return
    for raw_kw in keywords[:10]:
        kw = str(raw_kw).lower().strip()[:100]
        if not kw:
            continue
        existing = db.query(models.UserInterest).filter(
            models.UserInterest.user_id == user_id,
            models.UserInterest.keyword == kw
        ).first()
        if existing:
            existing.score = max(0.0, min(100.0, existing.score + delta))
            existing.updated_at = datetime.utcnow()
        elif delta > 0:
            db.add(models.UserInterest(user_id=user_id, keyword=kw, score=delta))

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
async def send_message(
    receiver_id: int = Form(...),
    content: Optional[str] = Form(None),
    reply_to_id: Optional[int] = Form(None),
    gif_url: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.id == receiver_id:
        raise HTTPException(status_code=400, detail="You cannot message yourself.")

    receiver = db.query(models.User).filter(models.User.id == receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")

    if not content and not image and not gif_url:
        raise HTTPException(status_code=400, detail="Message must have content or an image.")

    image_path = None
    if image:
        upload_dir = "app/static/message_images"
        os.makedirs(upload_dir, exist_ok=True)
        filename = f"msg_{uuid.uuid4().hex}.jpg"
        file_location = os.path.join(upload_dir, filename)
        data = await image.read()
        save_image_resized(data, file_location)
        image_path = f"/static/message_images/{filename}"
    elif gif_url:
        image_path = gif_url

    new_msg = models.Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content,
        image_url=image_path,
        reply_to_id=reply_to_id,
        timestamp=datetime.utcnow()
    )
    db.add(new_msg)
    db.commit()
    return {"status": "sent"}

# --- ADD THIS TO main.py ---

@app.get("/messages/conversation/{other_user_id}")
def get_conversation(
    other_user_id: int,
    skip: int = 0,
    limit: int = 30,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    messages = db.query(models.Message).options(
        joinedload(models.Message.reactions),
        joinedload(models.Message.reply_to),
    ).filter(
        ((models.Message.sender_id == current_user.id) & (models.Message.receiver_id == other_user_id)) |
        ((models.Message.sender_id == other_user_id) & (models.Message.receiver_id == current_user.id))
    ).order_by(models.Message.timestamp.desc()).offset(skip).limit(limit).all()

    messages.reverse()

    def msg_dict(m):
        return {
            "id": m.id,
            "content": m.content,
            "image_url": m.image_url,
            "sender_id": m.sender_id,
            "receiver_id": m.receiver_id,
            "timestamp": m.timestamp.isoformat(),
            "reply_to": {
                "id": m.reply_to.id,
                "content": m.reply_to.content,
                "image_url": m.reply_to.image_url,
                "sender_id": m.reply_to.sender_id,
            } if m.reply_to else None,
            "reactions": [
                {"emoji": r.emoji, "user_id": r.user_id}
                for r in (m.reactions or [])
            ],
        }

    return [msg_dict(m) for m in messages]


@app.post("/messages/{message_id}/react")
def react_to_message(
    message_id: int,
    emoji: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    existing = db.query(models.MessageReaction).filter_by(
        message_id=message_id, user_id=current_user.id
    ).first()

    if existing:
        if existing.emoji == emoji:
            db.delete(existing)
        else:
            existing.emoji = emoji
    else:
        db.add(models.MessageReaction(
            message_id=message_id,
            user_id=current_user.id,
            emoji=emoji,
        ))
    db.commit()
    return {"status": "ok"}

@app.delete("/messages/conversation/{other_user_id}")
def delete_conversation(
    other_user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    db.query(models.Message).filter(
        (
            (models.Message.sender_id == current_user.id) & (models.Message.receiver_id == other_user_id)
        ) | (
            (models.Message.sender_id == other_user_id) & (models.Message.receiver_id == current_user.id)
        )
    ).delete(synchronize_session=False)
    db.commit()
    return {"status": "deleted"}

@app.delete("/messages/{message_id}")
def delete_message(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your message")
    db.delete(msg)
    db.commit()
    return {"status": "deleted"}

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

@app.post("/users/heartbeat")
def heartbeat(current_user: models.User = Depends(get_current_user)):
    _last_seen[current_user.id] = _dt.utcnow()
    return {"status": "ok"}

@app.get("/users/{user_id}/online")
def get_online_status(user_id: int, current_user: models.User = Depends(get_current_user)):
    last = _last_seen.get(user_id)
    online = last is not None and (_dt.utcnow() - last).total_seconds() < 120
    return {"online": online}

@app.post("/messages/typing/{other_user_id}")
def set_typing(other_user_id: int, current_user: models.User = Depends(get_current_user)):
    if current_user.id not in _typing_state:
        _typing_state[current_user.id] = {}
    _typing_state[current_user.id][other_user_id] = _dt.utcnow()
    return {"status": "ok"}

@app.get("/messages/typing/{other_user_id}")
def get_typing(other_user_id: int, current_user: models.User = Depends(get_current_user)):
    ts = _typing_state.get(other_user_id, {}).get(current_user.id)
    typing = ts is not None and (_dt.utcnow() - ts).total_seconds() < 4
    return {"typing": typing}

@app.post("/groups/create")
def create_group(
    name: str = Form(...),
    member_ids: str = Form(...),  # comma-separated user IDs
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    ids = [int(i.strip()) for i in member_ids.split(',') if i.strip()]
    if current_user.id not in ids:
        ids.append(current_user.id)
    if len(ids) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 members")

    group = models.GroupChat(name=name.strip(), created_by=current_user.id)
    db.add(group)
    db.flush()
    for uid in ids:
        db.add(models.GroupMember(group_id=group.id, user_id=uid))
    db.commit()
    db.refresh(group)
    return {"id": group.id, "name": group.name}


@app.get("/groups/")
def list_groups(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    memberships = db.query(models.GroupMember).filter(
        models.GroupMember.user_id == current_user.id
    ).all()
    result = []
    for m in memberships:
        group = db.query(models.GroupChat).filter(models.GroupChat.id == m.group_id).first()
        if not group:
            continue
        last_msg = db.query(models.GroupMessage).filter(
            models.GroupMessage.group_id == group.id
        ).order_by(models.GroupMessage.timestamp.desc()).first()
        members = db.query(models.GroupMember).filter(
            models.GroupMember.group_id == group.id
        ).all()
        member_names = []
        for gm in members:
            u = db.query(models.User).filter(models.User.id == gm.user_id).first()
            if u:
                member_names.append(u.username)
        result.append({
            "id": group.id,
            "name": group.name,
            "member_count": len(members),
            "member_names": member_names,
            "last_message": last_msg.content if last_msg else None,
            "last_timestamp": last_msg.timestamp.isoformat() if last_msg else group.created_at.isoformat(),
        })
    result.sort(key=lambda x: x["last_timestamp"], reverse=True)
    return result


@app.get("/groups/{group_id}/messages")
def get_group_messages(
    group_id: int,
    skip: int = 0,
    limit: int = 30,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    member = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=current_user.id).first()
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    messages = db.query(models.GroupMessage).options(
        joinedload(models.GroupMessage.sender),
        joinedload(models.GroupMessage.reactions),
        joinedload(models.GroupMessage.reply_to),
    ).filter(models.GroupMessage.group_id == group_id).order_by(
        models.GroupMessage.timestamp.desc()
    ).offset(skip).limit(limit).all()
    messages.reverse()

    def msg_dict(m):
        return {
            "id": m.id,
            "content": m.content,
            "image_url": m.image_url,
            "sender_id": m.sender_id,
            "sender_username": m.sender.username if m.sender else "Unknown",
            "sender_avatar": m.sender.avatar_url if m.sender else None,
            "sender_avatar_version": m.sender.avatar_version or 1 if m.sender else 1,
            "timestamp": m.timestamp.isoformat(),
            "reply_to": {
                "id": m.reply_to.id,
                "content": m.reply_to.content,
                "image_url": m.reply_to.image_url,
                "sender_id": m.reply_to.sender_id,
            } if m.reply_to else None,
            "reactions": [{"emoji": r.emoji, "user_id": r.user_id} for r in (m.reactions or [])],
        }
    return [msg_dict(m) for m in messages]


@app.post("/groups/{group_id}/messages/send")
async def send_group_message(
    group_id: int,
    content: Optional[str] = Form(None),
    reply_to_id: Optional[int] = Form(None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    member = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=current_user.id).first()
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    if not content and not image:
        raise HTTPException(status_code=400, detail="Message must have content or an image.")

    image_path = None
    if image:
        upload_dir = "app/static/message_images"
        os.makedirs(upload_dir, exist_ok=True)
        filename = f"grpmsg_{uuid.uuid4().hex}.jpg"
        file_location = os.path.join(upload_dir, filename)
        data = await image.read()
        save_image_resized(data, file_location)
        image_path = f"/static/message_images/{filename}"

    msg = models.GroupMessage(
        group_id=group_id,
        sender_id=current_user.id,
        content=content,
        image_url=image_path,
        reply_to_id=reply_to_id,
        timestamp=datetime.utcnow(),
    )
    db.add(msg)
    db.commit()
    return {"status": "sent"}


@app.post("/groups/{group_id}/messages/{message_id}/react")
def react_group_message(
    group_id: int,
    message_id: int,
    emoji: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    member = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=current_user.id).first()
    if not member:
        raise HTTPException(status_code=403, detail="Not a member")
    existing = db.query(models.GroupMessageReaction).filter_by(
        message_id=message_id, user_id=current_user.id
    ).first()
    if existing:
        if existing.emoji == emoji:
            db.delete(existing)
        else:
            existing.emoji = emoji
    else:
        db.add(models.GroupMessageReaction(message_id=message_id, user_id=current_user.id, emoji=emoji))
    db.commit()
    return {"status": "ok"}


@app.delete("/groups/{group_id}/messages/{message_id}")
def delete_group_message(
    group_id: int,
    message_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    msg = db.query(models.GroupMessage).filter_by(id=message_id, group_id=group_id).first()
    if not msg:
        raise HTTPException(status_code=404)
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="Can only delete your own messages")
    db.delete(msg)
    db.commit()
    return {"status": "deleted"}


@app.post("/groups/{group_id}/leave")
def leave_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    member = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=current_user.id).first()
    if member:
        db.delete(member)
        db.commit()
    return {"status": "left"}


@app.get("/groups/{group_id}/info")
def get_group_info(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    member = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=current_user.id).first()
    if not member:
        raise HTTPException(status_code=403, detail="Not a member")
    group = db.query(models.GroupChat).filter_by(id=group_id).first()
    members = db.query(models.GroupMember).filter_by(group_id=group_id).all()
    member_list = []
    for gm in members:
        u = db.query(models.User).filter_by(id=gm.user_id).first()
        if u:
            member_list.append({"id": u.id, "username": u.username, "avatar_url": u.avatar_url, "avatar_version": u.avatar_version or 1})
    return {"id": group.id, "name": group.name, "created_by": group.created_by, "members": member_list}


@app.get("/messages/inbox")
def get_inbox(
    skip: int = 0,
    limit: int = 30,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
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
            "other_user_avatar": other_user.avatar_url,
            "other_user_avatar_version": other_user.avatar_version or 1,
            "timestamp": msg.timestamp.isoformat()
        })
    return results[skip: skip + limit]

@app.get("/users/search")
def search_users(q: str, skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    users = db.query(models.User).filter(
        models.User.username.ilike(f"%{q}%")
    ).offset(skip).limit(limit).all()

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

@app.get("/friends/sent-requests")
def get_sent_requests(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    sent = db.query(models.Friendship).options(
        joinedload(models.Friendship.receiver)
    ).filter(
        models.Friendship.user_id == current_user.id,
        models.Friendship.status == 'pending'
    ).all()
    return [{"user_id": s.friend_id} for s in sent]

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

@app.delete("/friends/{user_id}")
def unfriend(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    friendship = db.query(models.Friendship).filter(
        (
            (models.Friendship.user_id == current_user.id) & (models.Friendship.friend_id == user_id)
        ) | (
            (models.Friendship.user_id == user_id) & (models.Friendship.friend_id == current_user.id)
        ),
        models.Friendship.status == 'accepted'
    ).first()
    if not friendship:
        raise HTTPException(status_code=404, detail="Friendship not found")
    db.delete(friendship)
    db.commit()
    return {"status": "removed"}

@app.get("/friends/status/{user_id}")
def get_friend_status(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    friendship = db.query(models.Friendship).filter(
        (
            (models.Friendship.user_id == current_user.id) & (models.Friendship.friend_id == user_id)
        ) | (
            (models.Friendship.user_id == user_id) & (models.Friendship.friend_id == current_user.id)
        )
    ).first()
    if not friendship:
        return {"status": "none"}
    if friendship.status == 'accepted':
        return {"status": "friends"}
    if friendship.user_id == current_user.id:
        return {"status": "sent"}
    return {"status": "received"}

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

@app.get("/users/me/activity")
def get_my_activity(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    results = []

    # Likes on my UserPosts
    likes = db.query(models.UserPostLike).options(
        joinedload(models.UserPostLike.user),
        joinedload(models.UserPostLike.user_post)
    ).join(models.UserPost, models.UserPostLike.user_post_id == models.UserPost.id).filter(
        models.UserPost.user_id == current_user.id,
        models.UserPostLike.user_id != current_user.id
    ).order_by(models.UserPostLike.id.desc()).limit(30).all()

    for like in likes:
        if not like.user or not like.user_post:
            continue
        results.append({
            "type": "like",
            "actor_username": like.user.username,
            "actor_avatar": like.user.avatar_url,
            "actor_avatar_version": like.user.avatar_version or 1,
            "actor_id": like.user.id,
            "text": "liked your post",
            "preview": like.user_post.content[:80] if like.user_post.content else "",
            "user_post_id": like.user_post_id,
            "timestamp": like.user_post.created_at.isoformat() if like.user_post.created_at else ""
        })

    # Comments on my UserPosts
    comments = db.query(models.Comment).options(
        joinedload(models.Comment.author),
        joinedload(models.Comment.user_post)
    ).join(models.UserPost, models.Comment.user_post_id == models.UserPost.id).filter(
        models.UserPost.user_id == current_user.id,
        models.Comment.user_id != current_user.id
    ).order_by(models.Comment.timestamp.desc()).limit(30).all()

    for comment in comments:
        if not comment.author or not comment.user_post:
            continue
        results.append({
            "type": "comment",
            "actor_username": comment.author.username,
            "actor_avatar": comment.author.avatar_url,
            "actor_avatar_version": comment.author.avatar_version or 1,
            "actor_id": comment.author.id,
            "text": "commented on your post",
            "preview": comment.content[:80] if comment.content else "",
            "user_post_id": comment.user_post_id,
            "timestamp": comment.timestamp.isoformat() if comment.timestamp else ""
        })

    # Mentions (notifications)
    mentions = db.query(models.Notification).options(
        joinedload(models.Notification.sender)
    ).filter(
        models.Notification.user_id == current_user.id,
        models.Notification.type == "mention"
    ).order_by(models.Notification.timestamp.desc()).limit(20).all()

    for n in mentions:
        if not n.sender:
            continue
        results.append({
            "type": "mention",
            "actor_username": n.sender.username,
            "actor_avatar": n.sender.avatar_url,
            "actor_avatar_version": n.sender.avatar_version or 1,
            "actor_id": n.sender.id,
            "text": "mentioned you in a comment",
            "preview": "",
            "user_post_id": n.user_post_id,
            "timestamp": n.timestamp.isoformat() if n.timestamp else ""
        })

    results.sort(key=lambda x: x["timestamp"], reverse=True)
    return results[:50]

@app.get("/messages/search")
def search_messages(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    msgs = db.query(models.Message).options(
        joinedload(models.Message.sender),
        joinedload(models.Message.receiver)
    ).filter(
        (models.Message.sender_id == current_user.id) | (models.Message.receiver_id == current_user.id),
        models.Message.content.ilike(f"%{q}%")
    ).order_by(models.Message.timestamp.desc()).limit(20).all()

    results = []
    for m in msgs:
        other = m.receiver if m.sender_id == current_user.id else m.sender
        if not other:
            continue
        results.append({
            "message_id": m.id,
            "content": m.content,
            "timestamp": m.timestamp.isoformat(),
            "other_user_id": other.id,
            "other_user_name": other.username,
            "other_user_avatar": other.avatar_url,
            "other_user_avatar_version": other.avatar_version or 1,
        })
    return results

@app.get("/users/{user_id}")
def get_user_profile(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
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

@app.get("/users/{user_id}/posts")
def get_user_profile_posts(
    user_id: int,
    sort: str = "new",
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
):
    posts = db.query(models.UserPost).options(
        joinedload(models.UserPost.author),
        joinedload(models.UserPost.comments)
    ).filter(models.UserPost.user_id == user_id).all()

    for p in posts:
        p.like_count = db.query(models.UserPostLike).filter(
            models.UserPostLike.user_post_id == p.id, models.UserPostLike.vote_type == 1
        ).count()
        p.dislike_count = db.query(models.UserPostLike).filter(
            models.UserPostLike.user_post_id == p.id, models.UserPostLike.vote_type == -1
        ).count()
        p.comment_count = len(p.comments)
        p.user_vote = 0
        if current_user:
            vote = db.query(models.UserPostLike).filter(
                models.UserPostLike.user_post_id == p.id,
                models.UserPostLike.user_id == current_user.id
            ).first()
            if vote:
                p.user_vote = vote.vote_type

    if sort == "hot" or sort == "top":
        posts.sort(key=lambda p: p.like_count - p.dislike_count, reverse=True)
    elif sort == "controversial":
        def controversy_score(p):
            up, down = p.like_count, p.dislike_count
            total = up + down
            if total == 0:
                return 0
            return min(up, down) / (total + 1) * total
        posts.sort(key=controversy_score, reverse=True)
    else:
        posts.sort(key=lambda p: p.created_at, reverse=True)

    return posts[:50]


@app.get("/users/{user_id}/comments")
def get_user_profile_comments(
    user_id: int,
    db: Session = Depends(get_db)
):
    comments = db.query(models.Comment).options(
        joinedload(models.Comment.post),
        joinedload(models.Comment.user_post)
    ).filter(
        models.Comment.user_id == user_id,
        models.Comment.content != "[deleted]"
    ).order_by(desc(models.Comment.timestamp)).limit(50).all()

    result = []
    for c in comments:
        score = db.query(func.sum(models.CommentLike.vote_type)).filter(
            models.CommentLike.comment_id == c.id
        ).scalar() or 0

        if c.post_id:
            post_title = c.post.headline if c.post else "Unknown Post"
            post_type = "news"
        else:
            raw = c.user_post.content if c.user_post else "Unknown Post"
            post_title = (raw[:80] + "...") if len(raw) > 80 else raw
            post_type = "user_post"

        result.append({
            "id": c.id,
            "content": c.content,
            "timestamp": c.timestamp,
            "post_id": c.post_id,
            "user_post_id": c.user_post_id,
            "post_title": post_title,
            "post_type": post_type,
            "score": int(score),
        })
    return result


@app.get("/users/{user_id}/stats")
def get_user_profile_stats(
    user_id: int,
    db: Session = Depends(get_db)
):
    user_post_ids = [row[0] for row in db.query(models.UserPost.id).filter(
        models.UserPost.user_id == user_id
    ).all()]
    post_karma = 0
    if user_post_ids:
        post_karma = db.query(func.sum(models.UserPostLike.vote_type)).filter(
            models.UserPostLike.user_post_id.in_(user_post_ids)
        ).scalar() or 0

    comment_ids = [row[0] for row in db.query(models.Comment.id).filter(
        models.Comment.user_id == user_id
    ).all()]
    comment_karma = 0
    if comment_ids:
        comment_karma = db.query(func.sum(models.CommentLike.vote_type)).filter(
            models.CommentLike.comment_id.in_(comment_ids)
        ).scalar() or 0

    follower_count = db.query(models.Friendship).filter(
        models.Friendship.status == 'accepted',
        (models.Friendship.user_id == user_id) | (models.Friendship.friend_id == user_id)
    ).count()

    return {
        "post_karma": int(post_karma),
        "comment_karma": int(comment_karma),
        "follower_count": follower_count,
    }


@app.get("/users/{user_id}/followers")
def get_user_followers(user_id: int, db: Session = Depends(get_db)):
    friendships = db.query(models.Friendship).filter(
        models.Friendship.status == 'accepted',
        (models.Friendship.user_id == user_id) | (models.Friendship.friend_id == user_id)
    ).all()
    result = []
    for f in friendships:
        other_id = f.friend_id if f.user_id == user_id else f.user_id
        u = db.query(models.User).filter(models.User.id == other_id).first()
        if u:
            result.append({"id": u.id, "username": u.username, "avatar_url": u.avatar_url, "avatar_version": u.avatar_version or 1})
    return result


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

    # 2. Always save as .jpg after resize
    unique_filename = f"user_{current_user.id}.jpg"
    file_location = os.path.join(upload_dir, unique_filename)

    # 3. Read, resize, save
    try:
        contents = await file.read()
        save_image_resized(contents, file_location)
    except Exception as e:
        print(f"File Save Error: {e}")
        raise HTTPException(status_code=500, detail="Could not save file to disk")

    # 4. Update Database (Keep this)
    avatar_path = f"/static/avatars/{unique_filename}"
    current_user.avatar_url = avatar_path
    current_user.avatar_version = (current_user.avatar_version or 0) + 1

    db.commit()

    return {"avatar_url": avatar_path, "version": current_user.avatar_version}

@app.get("/user-posts", response_model=List[schemas.UserPost])
def get_user_posts(
    skip: int = 0,
    limit: int = 20,
    topic: Optional[str] = None,
    category: Optional[str] = None,
    sort: str = "new",
    time: str = "all",
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
):
    query = db.query(models.UserPost).options(
        joinedload(models.UserPost.author),
        joinedload(models.UserPost.comments)
    )

    # Filters
    filter_topic = category if category else topic
    if filter_topic and filter_topic != "All" and filter_topic != "":
        query = query.filter(models.UserPost.topic == filter_topic)

    if search:
        query = query.filter(models.UserPost.content.ilike(f"%{search}%"))

    if time != "all":
        now = datetime.utcnow()
        start_date = None
        if time == "24h": start_date = now - timedelta(hours=24)
        elif time == "week": start_date = now - timedelta(weeks=1)
        elif time == "month": start_date = now - timedelta(days=30)
        elif time == "year": start_date = now - timedelta(days=365)
        if start_date: query = query.filter(models.UserPost.created_at >= start_date)

    # Sorting
    if sort == "hot" or sort == "top":
        # Sort by total votes (magnitude)
        subquery = db.query(models.UserPostLike.user_post_id, func.count(models.UserPostLike.id).label('count')).group_by(models.UserPostLike.user_post_id).subquery()
        query = query.outerjoin(subquery, models.UserPost.id == subquery.c.user_post_id).order_by(desc(func.coalesce(subquery.c.count, 0)))
    else:
        query = query.order_by(desc(models.UserPost.created_at))

    posts = query.offset(skip).limit(limit).all()

    # Populate Vote Counts
    for p in posts:
        # Count Upvotes (1)
        p.like_count = db.query(models.UserPostLike).filter(models.UserPostLike.user_post_id == p.id, models.UserPostLike.vote_type == 1).count()
        # Count Downvotes (-1)
        p.dislike_count = db.query(models.UserPostLike).filter(models.UserPostLike.user_post_id == p.id, models.UserPostLike.vote_type == -1).count()
        p.comment_count = len(p.comments)

        # Determine current user's vote
        p.user_vote = 0
        if current_user:
            vote = db.query(models.UserPostLike).filter(models.UserPostLike.user_post_id == p.id, models.UserPostLike.user_id == current_user.id).first()
            if vote:
                p.user_vote = vote.vote_type

        # Populate comment scores for the UI
        populate_comment_scores(p.comments, db, current_user.id if current_user else None)

    return posts

@app.delete("/user-posts/{post_id}")
def delete_user_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    post = db.query(models.UserPost).filter(models.UserPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your post")
    db.delete(post)
    db.commit()
    return {"status": "deleted"}

NSFW_DOMAINS = {
    'pornhub.com', 'xvideos.com', 'xhamster.com', 'redtube.com', 'xnxx.com',
    'youporn.com', 'tube8.com', 'spankbang.com', 'beeg.com', 'drtuber.com',
    'tnaflix.com', 'onlyfans.com', 'fansly.com', 'chaturbate.com', 'livejasmin.com',
    'cam4.com', 'stripchat.com', 'bongacams.com', 'myfreecams.com', 'camsoda.com',
    'brazzers.com', 'bangbros.com', 'realitykings.com', 'mofos.com', 'naughtyamerica.com',
    'adultfriendfinder.com', 'ashleymadison.com',
}

@app.get("/link-preview")
def get_link_preview(url: str):
    # Validate URL format
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            raise HTTPException(status_code=400, detail="Invalid URL")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    # Check NSFW domains
    domain = parsed.netloc.lower().lstrip('www.')
    if any(domain == d or domain.endswith('.' + d) for d in NSFW_DOMAINS):
        raise HTTPException(status_code=400, detail="This link is not allowed")

    try:
        resp = requests.get(
            url,
            timeout=5,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; SkimsyBot/1.0)'},
            allow_redirects=True
        )
        resp.raise_for_status()
        content_type = resp.headers.get('content-type', '')
        if 'text/html' not in content_type:
            raise HTTPException(status_code=400, detail="URL does not point to a webpage")
    except requests.RequestException:
        raise HTTPException(status_code=400, detail="Could not fetch URL")

    soup = BeautifulSoup(resp.text, 'html.parser')

    # Title: og:title → twitter:title → <title>
    title = None
    for attr in [('property', 'og:title'), ('name', 'twitter:title')]:
        tag = soup.find('meta', {attr[0]: attr[1]})
        if tag and tag.get('content'):
            title = tag['content'].strip()
            break
    if not title:
        title_tag = soup.find('title')
        if title_tag:
            title = title_tag.get_text().strip()
    if not title:
        raise HTTPException(status_code=400, detail="Could not find article title")

    # Image: og:image → twitter:image
    image = None
    for attr in [('property', 'og:image'), ('name', 'twitter:image')]:
        tag = soup.find('meta', {attr[0]: attr[1]})
        if tag and tag.get('content'):
            image = tag['content'].strip()
            break

    return {"title": title[:200], "image": image, "url": url}


# --- ENSURE THIS FUNCTION EXISTS (Fixes 404 Error) ---
@app.post("/user-posts", response_model=schemas.UserPost)
async def create_user_post(
    content: str = Form(...),
    topic: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    image_url: Optional[str] = Form(None),
    link_url: Optional[str] = Form(None),
    link_title: Optional[str] = Form(None),
    link_image: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    image_path = image_url or None
    if image:
        upload_dir = "app/static/user_uploads"
        os.makedirs(upload_dir, exist_ok=True)
        filename = f"{uuid.uuid4()}.jpg"
        file_location = os.path.join(upload_dir, filename)
        save_image_resized(await image.read(), file_location)
        image_path = f"/static/user_uploads/{filename}"

    new_post = models.UserPost(
        user_id=current_user.id,
        content=content,
        topic=topic,
        image_url=image_path,
        link_url=link_url or None,
        link_title=link_title or None,
        link_image=link_image or None,
    )
    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    return new_post

@app.post("/user-posts/{post_id}/vote", response_model=schemas.VoteResponse)
def vote_user_post(
    post_id: int,
    vote_type: int, # Query parameter: ?vote_type=1 or ?vote_type=-1
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Check for existing vote
    existing_vote = db.query(models.UserPostLike).filter(
        models.UserPostLike.user_post_id == post_id,
        models.UserPostLike.user_id == current_user.id
    ).first()

    final_user_vote = vote_type

    if existing_vote:
        if existing_vote.vote_type == vote_type:
            # User clicked the same vote button -> Toggle OFF (remove vote)
            db.delete(existing_vote)
            final_user_vote = 0
        else:
            # User changed vote (Up -> Down or Down -> Up)
            existing_vote.vote_type = vote_type
    else:
        # Create new vote
        new_vote = models.UserPostLike(
            user_id=current_user.id,
            user_post_id=post_id,
            vote_type=vote_type
        )
        db.add(new_vote)

    db.commit()

    # Get fresh counts to return to frontend
    likes = db.query(models.UserPostLike).filter(models.UserPostLike.user_post_id == post_id, models.UserPostLike.vote_type == 1).count()
    dislikes = db.query(models.UserPostLike).filter(models.UserPostLike.user_post_id == post_id, models.UserPostLike.vote_type == -1).count()

    return {
        "like_count": likes,
        "dislike_count": dislikes,
        "user_vote": final_user_vote
    }

# --- UPDATED: Create Comment (Handle both Post types) ---
@app.post("/comments", response_model=schemas.Comment)
async def create_comment(
    content: str = Form(...),
    post_id: Optional[int] = Form(None),       # Changed to Optional
    user_post_id: Optional[int] = Form(None),  # Added this field
    parent_id: Optional[int] = Form(None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. Validation: Must have at least one ID
    if not post_id and not user_post_id:
         raise HTTPException(status_code=400, detail="Must provide post_id or user_post_id")

    # 2. Handle Image Upload
    image_path = None
    if image:
        upload_dir = "app/static/comment_images"
        os.makedirs(upload_dir, exist_ok=True)
        filename = f"{uuid.uuid4()}.jpg"
        file_location = os.path.join(upload_dir, filename)
        save_image_resized(await image.read(), file_location)
        image_path = f"/static/comment_images/{filename}"

    # 3. Create Comment
    new_comment = models.Comment(
        content=content,
        post_id=post_id,          # Can be None now
        user_post_id=user_post_id,# Can be None now
        parent_id=parent_id,
        user_id=current_user.id,
        image_url=image_path
    )
    db.add(new_comment)
    db.flush() # Flush to get ID

    # 4. Auto-Upvote own comment
    auto_like = models.CommentLike(
        user_id=current_user.id,
        comment_id=new_comment.id,
        vote_type=1
    )
    db.add(auto_like)

    # 5. Handle Notifications (Mentions)
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
                post_id=post_id,             # Might be None
                user_post_id=user_post_id,   # Might be None
                comment_id=new_comment.id,
                type="mention",
                timestamp=datetime.utcnow()
            )
            db.add(notification)

    # Boost interests when commenting on a news post (strong intent signal)
    if post_id:
        news_post = db.query(models.Post).filter(models.Post.id == post_id).first()
        if news_post and news_post.keywords:
            update_user_interests(db, current_user.id, news_post.keywords, 5.0)

    db.commit()

    # 6. Return Result with formatted Author
    db_comment = db.query(models.Comment).options(joinedload(models.Comment.author)).filter(models.Comment.id == new_comment.id).first()
    db_comment.score = 1
    db_comment.user_vote = 1

    return db_comment

@app.get("/user-posts/{post_id}", response_model=schemas.UserPost)
def get_user_post_detail(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_optional_current_user)
):
    post = db.query(models.UserPost).options(
        joinedload(models.UserPost.author),
        joinedload(models.UserPost.comments).joinedload(models.Comment.author)
    ).filter(models.UserPost.id == post_id).first()

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Count Upvotes
    post.like_count = db.query(models.UserPostLike).filter(models.UserPostLike.user_post_id == post.id, models.UserPostLike.vote_type == 1).count()
    # Count Downvotes
    post.dislike_count = db.query(models.UserPostLike).filter(models.UserPostLike.user_post_id == post.id, models.UserPostLike.vote_type == -1).count()
    post.comment_count = len(post.comments)

    # Determine User Vote
    post.user_vote = 0
    if current_user:
        vote = db.query(models.UserPostLike).filter(models.UserPostLike.user_post_id == post.id, models.UserPostLike.user_id == current_user.id).first()
        if vote:
            post.user_vote = vote.vote_type

    populate_comment_scores(post.comments, db, current_user.id if current_user else None)
    return post
