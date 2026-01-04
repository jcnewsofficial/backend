from fastapi import FastAPI, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc
from typing import List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

from . import models, schemas, database
from .scraper import auto_parse_news
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, get_db
from typing import Optional

# --- SECURITY CONFIGURATION ---
SECRET_KEY = "DEVELOPMENT_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 week

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- DB INIT ---
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="JC News Backend")

origins = [
    "http://localhost:8081",
    "http://192.168.1.99:8081",
    "https://miic_pc-anonymous-8081.exp.direct", # Add this specific URL from your logs
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For development, using "*" is easiest to stop CORS errors
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

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
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

# --- AUTH ENDPOINTS ---

@app.post("/register", response_model=schemas.User)
def register(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    # Check if user exists
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash and save
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
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- NEWS & FEED ENDPOINTS ---

def get_optional_current_user(db: Session = Depends(get_db)):
    # This is a placeholder logic
    # In a real app, you'd check the Authorization header/token here
    try:
        # If you have auth logic, call it here
        # user = get_current_user(token, db)
        # return user
        return None
    except:
        return None

@app.get("/feed", response_model=List[schemas.Post])
def read_posts(db: Session = Depends(database.get_db), current_user: Optional[models.User] = Depends(get_optional_current_user)):
    try:
        # Just get the posts and comments.
        # Do NOT try to joinedload(models.Like.user) here.
        posts = db.query(models.Post).options(
            joinedload(models.Post.comments).joinedload(models.Comment.author)
        ).all()

        for post in posts:
            # We count by filtering the ID, which doesn't require a 'user' relationship
            post.like_count = db.query(models.Like).filter(
                models.Like.post_id == post.id,
                models.Like.vote_type == 1
            ).count()

            post.dislike_count = db.query(models.Like).filter(
                models.Like.post_id == post.id,
                models.Like.vote_type == -1
            ).count()

            post.user_vote = 0
            if current_user:
                vote = db.query(models.Like).filter(
                    models.Like.post_id == post.id,
                    models.Like.user_id == current_user.id
                ).first()
                if vote:
                    post.user_vote = vote.vote_type

        return posts
    except Exception as e:
        print(f"BACKEND ERROR: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auto-scrape", status_code=201)
async def create_automated_post(url: str, category: str, db: Session = Depends(database.get_db)):
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

# --- SOCIAL ENDPOINTS (SECURED) ---

@app.post("/comments", response_model=schemas.Comment)
def create_comment(
    comment: schemas.CommentCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    new_comment = models.Comment(
        content=comment.content,
        post_id=comment.post_id,
        user_id=current_user.id,
        parent_id=comment.parent_id # Save the parent_id if it exists
    )
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)
    return new_comment

@app.post("/posts/{post_id}/like")
def like_post(
    post_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Check if already liked
    existing_like = db.query(models.Like).filter(
        models.Like.post_id == post_id,
        models.Like.user_id == current_user.id
    ).first()

    if existing_like:
        db.delete(existing_like)
        db.commit()
        return {"message": "Unliked"}

    new_like = models.Like(post_id=post_id, user_id=current_user.id)
    db.add(new_like)
    db.commit()
    return {"message": "Liked"}

@app.post("/posts/{post_id}/vote")
def vote_post(post_id: int, vote_type: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # 1. Check if vote already exists
    existing_vote = db.query(models.Like).filter(
        models.Like.post_id == post_id,
        models.Like.user_id == current_user.id
    ).first()

    if existing_vote:
        if existing_vote.vote_type == vote_type:
            # User clicked the same button again -> Undo/Delete
            db.delete(existing_vote)
        else:
            # User switched from like to dislike or vice versa -> Update
            existing_vote.vote_type = vote_type
    else:
        # New vote
        new_vote = models.Like(user_id=current_user.id, post_id=post_id, vote_type=vote_type)
        db.add(new_vote)

    db.commit()
    return {"status": "success"}
