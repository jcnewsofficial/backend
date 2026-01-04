from fastapi import FastAPI, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

from . import models, schemas, database
from .scraper import auto_parse_news
from fastapi.middleware.cors import CORSMiddleware

# --- SECURITY CONFIGURATION ---
SECRET_KEY = "DEVELOPMENT_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 week

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

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
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    new_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- NEWS & FEED ENDPOINTS ---

@app.get("/feed", response_model=List[schemas.Post])
def read_posts(skip: int = 0, limit: int = 20, db: Session = Depends(database.get_db)):
    return db.query(models.Post).order_by(desc(models.Post.id)).offset(skip).limit(limit).all()

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
    current_user: models.User = Depends(get_current_user) # Now requires login
):
    new_comment = models.Comment(
        content=comment.content,
        post_id=comment.post_id,
        user_id=current_user.id
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
