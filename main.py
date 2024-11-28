from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import sqlite3
import auth

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database initialization
def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    hashed_password TEXT
                )""")
    return conn

# Pydantic models
class User(BaseModel):
    username: str
    password: str

class UserInDB(BaseModel):
    username: str
    hashed_password: str


class UserUpdate(BaseModel):
    username: str
    password: Optional[str] = None

# Helper functions
def create_user(username: str, password: str):
    db = get_db()
    hashed_password = auth.hash_password(password)
    try:
        db.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, hashed_password))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")

def get_user_by_username(username: str):
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user:
        return UserInDB(username=user[1], hashed_password=user[2])
    return None

def update_user(username: str, password: Optional[str] = None):
    db = get_db()
    if password:
        hashed_password = auth.hash_password(password)
        db.execute("UPDATE users SET hashed_password = ? WHERE username = ?", (hashed_password, username))
        db.commit()

def delete_user(username: str):
    db = get_db()
    db.execute("DELETE FROM users WHERE username = ?", (username,))
    db.commit()

# Routes
@app.post("/signup")
def signup(user: User):
    create_user(user.username, user.password)
    return {"message": "User created successfully"}

@app.get("/users/{username}")
def read_user(username: str):
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user.username}

@app.put("/users/{username}")
def update_user_endpoint(username: str, user_update: UserUpdate):
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    update_user(username, user_update.password)
    return {"message": "User updated successfully"}

@app.delete("/users/{username}")
def delete_user_endpoint(username: str):
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    delete_user(username)
    return {"message": "User deleted successfully"}

@app.post("/signin")
def signin(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(form_data.username)
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    # Return a token (dummy here for demonstration)
    return {"message": "Login successful", "token": "dummy_token"}

@app.post("/reset-password")
def reset_password(reset_data: UserUpdate):
    user = get_user_by_username(reset_data.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if reset_data.password:
        update_user(reset_data.username, reset_data.password)
    return {"message": "Password reset successful"}

@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    return {"message": "Logout successful"}
