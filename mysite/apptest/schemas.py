from ninja import Schema
from pydantic import  EmailStr, Field

class UserCreateSchema(Schema):
    email: EmailStr
    password: str = Field(min_lenght= 8, max_length=200)

class AuthSchema(Schema):
    email: EmailStr
    password: str = Field(min_length = 8, max_length=200)