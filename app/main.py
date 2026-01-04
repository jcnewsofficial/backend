from fastapi import FastAPI, Depends, HTTPException, Response, status, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

from . import models, schemas, database
from .scraper import auto_parse_news
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, get_db

# --- SECURITY CONFIGURATION ---
SECRET_KEY = "DEVELOPMENT_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 week

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

# --- DB INIT ---
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="JC News Backend")

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

@app.post("/auto-scrape", status_code=201)
async def create_automated_post(url: str, category: str, db: Session = Depends(get_db)):
    try:
        scraped_data = auto_parse_news(url)
        new_post = models.Post(
            headline=scraped_data["headline"],
            image_url=scraped_data.get("image_url", "https://example.com/default.jpg"),
            category=category,
            bullet_points=scraped_data["bullets"],
            source_url=url
        )
        db.add(new_post)
        db.commit()
        db.refresh(new_post)
        return {"status": "success", "post_id": new_post.id}
    except Exception as e:
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
    db.refresh(new_comment)
    return new_comment

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
