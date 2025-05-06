import pytest
from pydantic import ValidationError
from core.validations import UserCredentials, PasswordEntryData, HttpUrl

# --- Тесты для UserCredentials ---

def test_user_credentials_valid():
    valid_data = {'login': 'testuser', 'password': 'ValidPass123'}
    user = UserCredentials(**valid_data)
    assert user.login == valid_data['login']
    assert user.password == valid_data['password']

@pytest.mark.parametrize(
    "invalid_data, expected_error_part",
    [
        ({'login': 'us', 'password': 'ValidPass123'}, 'login'), # Короткий логин
        ({'login': 'user', 'password': 'short1'}, 'password'),   # Короткий пароль
        ({'login': 'user', 'password': 'nonumber'}, 'password'), # Пароль без цифр
        ({'login': 'user', 'password': 'NOCAPS123'}, 'password'), # Пароль без строчных
        ({'login': 'user', 'password': 'nocaps123'}, 'password'), # Пароль без заглавных
        ({'login': 'longpassuser', 'password': 'a' * 129 + 'B1'}, 'password'), # Слишком длинный
        ({}, 'login'), # Нет обязательных полей
    ]
)

def test_user_credentials_invalid(invalid_data, expected_error_part):
    with pytest.raises(ValidationError) as excinfo:
        UserCredentials(**invalid_data)
    assert expected_error_part in str(excinfo.value).lower()

# --- Тесты для PasswordEntryData ---

def test_password_entry_valid_all_fields():
    valid_data = {
        'service_name': 'Google',
        'username': 'test@example.com',
        'password': 'complex_password!@#',
        'url': 'https://google.com/path',
        'notes': "Какие то важные заметки."
    }
    entry = PasswordEntryData(**valid_data)
    assert entry.service_name == valid_data['service_name']
    assert entry.username == valid_data['username']
    assert entry.password == valid_data['password']
    assert str(entry.url) == valid_data['url']
    assert entry.notes == valid_data['notes']

def test_password_entry_valid_required_only():
    valid_data = {
        'service_name': "Local Site",
        'username': 'admin',
        'password': 'pwd'
    }
    entry = PasswordEntryData(**valid_data)
    assert entry.service_name == valid_data['service_name']
    assert entry.username == valid_data['username']
    assert entry.password == valid_data['password']
    assert entry.url is None
    assert entry.notes is None

@pytest.mark.parametrize(
    "invalid_data, expected_error_part",
    [
        ({'service_name': "", 'username': 'usr', 'password': 'pwd'}, 'service_name'),
        ({'service_name': 's', 'username': "", 'password': 'pwd'}, 'username'),
        ({'service_name': 's', 'username': 'usr', 'password': ""}, 'password'),
        ({'service_name': 's', 'username': 'usr', 'password': 'pwd', 'url': "not-a-url"}, 'url'),
        ({'service_name': 's', 'username': 'usr', 'password': 'pwd', 'url': "ftp://site.com"}, 'url'),
    ]
)
def test_password_entry_invalid(invalid_data, expected_error_part):
    with pytest.raises(ValidationError) as excinfo:
        PasswordEntryData(**invalid_data)
    assert expected_error_part in str(excinfo.value).lower()