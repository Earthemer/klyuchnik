import re
import logging
from pydantic import (
    BaseModel,
    Field,
    EmailStr,
    HttpUrl,
    validator,
    ValidationError,
    field_validator
)

logger = logging.getLogger(__name__)

#Проверка данных пользователя
class UserCredentials(BaseModel):
    login: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8)

    @field_validator('password', mode='after')
    def password_complexity(cls, v: str) -> str:
        """Проверяет сложность пароля (примерные правила)."""
        if len(v) < 8:
            raise ValueError('Пароль должен быть не менее 8 символов')
        if not re.search(r"[A-Z]", v):  # Должна быть хотя бы одна заглавная буква
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        if not re.search(r"[a-z]", v):  # Должна быть хотя бы одна строчная буква
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        if not re.search(r"\d", v):  # Должна быть хотя бы одна цифра
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        logger.debug("Сложность пароля подтверждена.")
        return v

#Проверка данных для записи
class PasswordEntryData(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=255)
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1)
    url: HttpUrl | None = None
    notes: str | None = None


