from pydantic import BaseModel,EmailStr
from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

# class User(BaseModel):
#     name:str
#     email:EmailStr
#     password:str
#     role:str
#     is_active:Optional[bool]=False

# class Login(BaseModel):
#     email:EmailStr
#     password:str

# class Post(BaseModel):
#     title: str
#     body: str
#     author_id: str
#     featured: Optional[bool] = False

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=72)

class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class OTPVerify(BaseModel):
    user_id: str
    otp: str = Field(..., min_length=6, max_length=6)

class PasswordUpdate(BaseModel):
    user_id: str
    password: str = Field(..., min_length=6, max_length=72)

class PostCreate(BaseModel):
    title: str
    body: str

class LikeToggle(BaseModel):
    user_id: str
    post_id: str
    created_at: datetime

class View(BaseModel):
    user_id: str
    post_id: str
    created_at: datetime

class AdminCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class AdminLoginSchema(BaseModel):
    email: str
    password: str