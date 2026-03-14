from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from dotenv import load_dotenv
from datetime import datetime
from model import UserCreate, LoginSchema, OTPVerify, PasswordUpdate, PostCreate, LikeToggle, View, AdminCreate, AdminLoginSchema
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from astrapy import DataAPIClient
from utilities import hashedpassword, verifyHashed, generate_otp, send_email

from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer
from datetime import timedelta, timezone

import uuid

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ph = PasswordHasher()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# -----------------------------
# Astra DB Setup
# -----------------------------

token_db = os.getenv("DB_TOKEN")

client = DataAPIClient(token_db)
db = client.get_database_by_api_endpoint(
    "https://b054facc-a4a3-492a-88c9-db1090c0a4ba-us-east-2.apps.astra.datastax.com"
)
print(f"Connected to Astra DB: {db.list_collection_names()}")
# Use get_collection (NOT create_collection)
user_collection = db.get_collection("Users")
post_collection = db.get_collection("Posts")
like_collection = db.get_collection("Likes") 
view_collection = db.get_collection("Views")

# -----------------------------
# FastAPI App
# -----------------------------

app = FastAPI(
    title="Revival API",
    version="2.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all origins (DEV ONLY)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# ADMIN DEPENDENCY
# -----------------------------

def admin_required(user_id: str):
    user = user_collection.find_one({"_id": user_id})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -----------------------------
# AUTH DEPENDENCIES
# -----------------------------

async def get_current_user(token: str = Depends(oauth2_scheme)):
    print("TOKEN RECEIVED:", token)  # add this
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("PAYLOAD:", payload)  # and this
        user_id: str = payload.get("id")

        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

    except JWTError as e:
        print("JWT ERROR:", e)  # and this
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = user_collection.find_one({"_id": user_id})
    print("USER FOUND:", user)  # and this

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


async def admin_required(current_user: dict = Depends(get_current_user)):

    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return current_user

def verify_password(plain_password, hashed_password):
    try:
        return ph.verify(hashed_password, plain_password)  # note: hashed first, plain second
    except VerifyMismatchError:
        return False

# -----------------------------
# AUTH ROUTES
# -----------------------------

@app.post("/signup", status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def signup(user: UserCreate):

    existing_user = user_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    otp = generate_otp()

    new_user = {
        "name": user.name,
        "email": user.email,
        "password": hashedpassword(user.password[:72]),
        "role": "user",  # default role
        "otp": otp,
        "is_active": False,
        "created_at": datetime.utcnow().isoformat()
    }

    result = user_collection.insert_one(new_user)

    try:
        send_email(user.email, "Revival Network Commisiion OTP Verification", f"Welcome to Revival Network Commission, Your OTP code is {otp}")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to send OTP email")

    return {
        "message": "User created successfully. Check your email for OTP.",
        "user": {
        "id": str(result.inserted_id)
    }
    }
    


@app.post("/verify-otp", tags=["Auth"])
async def verify_otp(payload: OTPVerify):

    user = user_collection.find_one({"_id": payload.user_id})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.get("otp") != payload.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user_collection.update_one(
        {"_id": payload.user_id},
        {"$set": {"is_active": True}, "$unset": {"otp": ""}}
    )

    return {"message": "OTP verified successfully"}


@app.post("/login", tags=["Auth"])
async def login(login: LoginSchema):
    user = user_collection.find_one({"email": login.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verifyHashed(user["password"], login.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    if not user.get("is_active"):
        raise HTTPException(status_code=403, detail="Account not verified")

    access_token = create_access_token({"user_id": user["_id"]})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(user["_id"]),
            "name": user.get("name") or user.get("username") or user.get("email"),
            "email": user.get("email"),
            "role": user.get("role", "user")
        }
    }


@app.post("/update-password", tags=["Auth"])
async def update_password(payload: PasswordUpdate):

    user = user_collection.find_one({"_id": payload.user_id})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_collection.update_one(
        {"_id": payload.user_id},
        {"$set": {"password": hashedpassword(payload.password[:72])}}
    )

    return {"message": "Password updated successfully"}

# -----------------------------
# USER ROUTES
# -----------------------------



@app.delete("/users/{user_id}", tags=["Users"])
async def delete_user(user_id: str):

    user = user_collection.find_one({"_id": user_id})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_collection.delete_one({"_id": user_id})

    return {"message": "User deleted successfully"}

# -----------------------------
# POSTS ROUTES
# -----------------------------

@app.post("/create_posts", tags=["Posts"])
async def create_post(post: PostCreate):

    post_collection.insert_one({
        "title": post.title,
        "body": post.body,
        "featured": False,
        "views": 0, 
        "created_at": datetime.utcnow().isoformat()
    })

    return {"message": "Post created successfully"}


@app.get("/posts")
async def get_posts(page: int = 1, limit: int = 7, search: str = ""):
    all_posts = list(post_collection.find())
    all_posts.sort(key=lambda p: p.get("created_at") or "", reverse=True)

    if search:
        all_posts = [p for p in all_posts if search.lower() in (p.get("title") or "").lower()]

    total = len(all_posts)
    start = (page - 1) * limit
    paginated = [serialize(p) for p in all_posts[start : start + limit]]

    return {"posts": paginated, "total": total}  # total is the key fix

@app.get("/posts/{post_id}", tags=["Posts"])
async def get_post(post_id: str):
    post = post_collection.find_one({"_id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Increment views
    post_collection.update_one(
        {"_id": post_id},
        {"$inc": {"views": 1}}
    )

    return {"post": post}


@app.post("/posts/{post_id}/like")
async def toggle_like(post_id: str, current_user: dict = Depends(get_current_user)):

    user_id = str(current_user["_id"])

    existing_like = like_collection.find_one({
        "user_id": user_id,
        "post_id": post_id
    })

    if existing_like:
        like_collection.delete_one({
            "user_id": user_id,
            "post_id": post_id
        })

        post_collection.update_one(
            {"_id": post_id},
            {"$inc": {"likes": -1}}
        )

        user_liked = False
    else:
        like_collection.insert_one({
            "user_id": user_id,
            "post_id": post_id
        })

        post_collection.update_one(
            {"_id": post_id},
            {"$inc": {"likes": 1}}
        )

        user_liked = True

    updated_post = post_collection.find_one({"_id": post_id})

    return {
        "likes": updated_post.get("likes", 0),
        "user_liked": user_liked
    }


@app.get("/posts/{post_id}")
async def get_post(post_id: str, current_user: dict = Depends(get_current_user)):

    user_id = str(current_user["_id"])

    post = post_collection.find_one({"_id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Check if user already viewed
    existing_view = view_collection.find_one({
        "user_id": user_id,
        "post_id": post_id
    })

    if not existing_view:
        view_collection.insert_one({
            "user_id": user_id,
            "post_id": post_id
        })

        post_collection.update_one(
            {"_id": post_id},
            {"$inc": {"views": 1}}
        )

        post = post_collection.find_one({"_id": post_id})

    post["_id"] = str(post["_id"])

    return {"post": post}


@app.get("/posts/{post_id}")
async def get_post(post_id: str):
    post = post_collection.find_one({"_id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Increment views
    post_collection.update_one(
        {"_id": post_id},
        {"$inc": {"views": 1}}
    )

    # Get updated post
    updated_post = post_collection.find_one({"_id": post_id})
    updated_post["_id"] = str(updated_post["_id"])

    return {"post": updated_post}


# -----------------------------
# ADMIN ROUTES
# -----------------------------
@app.post("/create-first-admin", tags=["Setup"])
async def create_first_admin(admin: AdminCreate):
    try:
        existing_admin = user_collection.find_one({"role": "admin"})
        if existing_admin:
            raise HTTPException(
                status_code=400,
                detail="Admin already exists"
            )

        new_admin = {
            "name": admin.name,
            "email": admin.email,
            "password": hashedpassword(admin.password[:72]),
            "role": "admin",
            "is_active": True,
            "created_at": datetime.utcnow().isoformat()
        }

        result = user_collection.insert_one(new_admin)

        return {
            "message": "First admin created successfully",
            "admin": {
                "id": str(new_admin["_id"]),
                "name": new_admin["name"],
                "email": new_admin["email"]
            }
        }
    
    except Exception as e:
        print("ERROR creating admin:", e)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {e}"
        )
    

@app.post("/create-first-admin2")
async def create_first_admin():
    existing = user_collection.find_one({"role": "admin"})
    if existing:
        raise HTTPException(status_code=400, detail="Admin already exists")

    user_id = str(uuid.uuid4())  # generate ID before insert

    admin_data = {
        "_id": user_id,  # set it explicitly
        "email": "admin@example.com",
        "password": hashedpassword("yourpassword"),
        "role": "admin",
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    user_collection.insert_one(admin_data)

    return {
        "message": "Admin created successfully",
        "id": user_id  # use the ID you already know
    }


from bson import ObjectId

# ── helpers ────────────────────────────────────────────────
def serialize(doc: dict) -> dict:
    """Convert ObjectId fields to strings."""
    doc["_id"] = str(doc["_id"])
    return doc


# ── auth ───────────────────────────────────────────────────
@app.post("/admin/login")
async def admin_login(user: AdminLoginSchema):
    admin = user_collection.find_one({"email": user.email})
    if not admin or not verify_password(user.password, admin["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if admin.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    token = create_access_token({"id": str(admin["_id"]), "role": admin["role"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": str(admin["_id"]), "email": admin["email"], "role": admin["role"]},
    }





# ── users ──────────────────────────────────────────────────
@app.get("/admin/users", tags=["Admin"])
async def get_all_users(admin: dict = Depends(admin_required)):
    users = []
    for user in user_collection.find():
        user.pop("password", None)
        user.pop("otp", None)
        users.append(serialize(user))
    print("SAMPLE USER:", users[0] if users else "no users")  # add this
    return {"users": users}


@app.delete("/admin/users/{user_id}", tags=["Admin"])
async def delete_user(user_id: str, admin: dict = Depends(admin_required)):
    result = user_collection.delete_one({"_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}


@app.put("/admin/users/{user_id}/role", tags=["Admin"])
async def update_user_role(user_id: str, body: dict, admin: dict = Depends(admin_required)):
    role = body.get("role")
    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    
    user = user_collection.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_collection.update_one({"_id": user_id}, {"$set": {"role": role}})
    return {"message": "Role updated"}


# ── posts ──────────────────────────────────────────────────
@app.get("/admin/posts", tags=["Admin"])
async def get_all_posts(admin: dict = Depends(admin_required)):
    posts = [serialize(p) for p in post_collection.find().sort("created_at", -1)]
    return {"posts": posts}


@app.post("/admin/posts", tags=["Admin"])
async def create_post(body: dict, admin: dict = Depends(admin_required)):
    body["created_at"] = datetime.now(timezone.utc).isoformat()  # store as string
    result = post_collection.insert_one(body)
    body["_id"] = str(result.inserted_id)
    return body


@app.put("/admin/posts/{post_id}", tags=["Admin"])
async def update_post(post_id: str, body: dict, admin: dict = Depends(admin_required)):
    print("BODY RECEIVED:", body)  # check what frontend is sending
    try:
        post = post_collection.find_one({"_id": post_id})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")
        
        post_collection.update_one(
            {"_id": post_id},
            {"$set": {
                "title": body.get("title"),
                "content": body.get("content"),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        return {"message": "Post updated"}
    except Exception as e:
        print("UPDATE ERROR:", e)  # see the exact error
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/admin/posts/{post_id}", tags=["Admin"])
async def delete_post(post_id: str, admin: dict = Depends(admin_required)):
    result = post_collection.delete_one({"_id": post_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Post not found")
    return {"message": "Post deleted successfully"}


@app.put("/admin/posts/{post_id}/toggle-featured", tags=["Admin"])
async def toggle_featured(post_id: str, admin: dict = Depends(admin_required)):

    post = post_collection.find_one({"_id": post_id})

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    new_value = not post.get("featured", False)

    post_collection.update_one(
        {"_id": post_id},
        {"$set": {"featured": new_value}}
    )

    return {"message": "Updated", "featured": new_value}

# ── dashboard ──────────────────────────────────────────────
@app.get("/admin/dashboard", tags=["Admin"])
async def get_dashboard(admin: dict = Depends(admin_required)):
    total_posts = len(list(post_collection.find({})))
    total_users = len(list(user_collection.find({})))
    recent_posts = [serialize(p) for p in post_collection.find().limit(5)]
    return {
        "total_posts": total_posts,
        "total_users": total_users,
        "recent_posts": recent_posts
    }

# new_hashed_password = pwd_context.hash("deji1226")
# user_collection.update_one(
#     {"email": "ayodejioladeji12@gmail.com"},  # replace with your admin email
#     {"$set": {"password": new_hashed_password}}
# )

# print("Password updated:", new_hashed_password)

import threading
import time
import requests

def keep_alive():
    while True:
        time.sleep(20 * 60 * 60)  # 20 hours
        try:
            # Ping your own API to keep Astra active
            requests.get("http://localhost:8000/ping", timeout=10)
            print("Keep-alive ping sent")
        except Exception as e:
            print("Keep-alive error:", e)

@app.get("/ping", tags=["Health"])
async def ping():
    # Touches the database so Astra registers activity
    user_collection.find_one({})
    return {"status": "ok"}

# Start keep-alive thread when app starts
@app.on_event("startup")
async def startup_event():
    thread = threading.Thread(target=keep_alive, daemon=True)
    thread.start()
    print("Keep-alive thread started")