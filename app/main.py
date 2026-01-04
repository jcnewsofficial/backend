from fastapi import FastAPI, Depends, HTTPException
from .scraper import auto_parse_news
from sqlalchemy.orm import Session
from typing import List
from . import models, schemas, database

# Create the database tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="JC News Backend")

@app.post("/auto-scrape", status_code=201)
async def create_automated_post(url: str, category: str, db: Session = Depends(database.get_db)):
    try:
        # 1. Run the scraper logic
        scraped_data = auto_parse_news(url)
        
        # 2. Create the Database Object
        new_post = models.Post(
            headline=scraped_data["headline"],
            image_url=scraped_data.get("image_url", "https://example.com/default.jpg"),
            category=category,
            bullet_points=scraped_data["bullets"],
            source_url=url
        )
        
        # 3. Save to Postgres
        db.add(new_post)
        db.commit()
        db.refresh(new_post)
        
        return {"status": "success", "post_id": new_post.id}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- NEWS FEED ENDPOINT ---
@app.get("/feed", response_model=List[schemas.Post])
def read_posts(skip: int = 0, limit: int = 20, db: Session = Depends(database.get_db)):
    posts = db.query(models.Post).offset(skip).limit(limit).all()
    return posts

# --- COMMENTING ENDPOINT ---
@app.post("/comments", response_model=schemas.Comment)
def create_comment(comment: schemas.CommentCreate, db: Session = Depends(database.get_db)):
    # Note: In a real app, you'd get the current_user ID from a JWT token
    new_comment = models.Comment(
        content=comment.content, 
        post_id=comment.post_id, 
        user_id=1 # Temporary placeholder
    )
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)
    return new_comment

# --- USER REGISTRATION ---
@app.post("/register", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Simple hash placeholder - use passlib for real apps!
    hashed_pass = user.password + "notsecurehash" 
    new_user = models.User(username=user.username, email=user.email, hashed_password=hashed_pass)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
