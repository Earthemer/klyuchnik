import pytest
import os
import base64
from core.crypto_handler import CryptoHandler

#создаем фикстуры, чтобы не дублировать создание объектов в тестах.
@pytest.fixture(scope="module")
def crypto_handler_fast():
    return CryptoHandler(iterations=1)

#Простой пароль
@pytest.fixture
def sample_password():
    return 'MySecretPassword123!'

#Данные в байтах для шифрования
@pytest.fixture
def sample_data():
    return b"this is the data to be encrypted."

#Генерируем соль
@pytest.fixture
def unique_salt(crypto_handler_fast):
    return crypto_handler_fast.get_salt()

#Тестовые функции:

def test_get_salt_returns_bytes_correct_length(crypto_handler_fast, unique_salt):
    assert isinstance(unique_salt, bytes)
    assert len(unique_salt) == crypto_handler_fast._DEFAULT_SALT_SIZE

def test_hash_salt_password_returns_bytes(crypto_handler_fast, sample_password, unique_salt):
    hashed_password = crypto_handler_fast.hash_password(sample_password, unique_salt)
    assert isinstance(hashed_password, bytes)
    assert len(hashed_password) == crypto_handler_fast._HASH_ALGORITHM.digest_size

def test_verify_password_correct(crypto_handler_fast, sample_password, unique_salt):
    stored_hash = crypto_handler_fast.hash_password(sample_password, unique_salt)
    is_valid = crypto_handler_fast.verify_password(stored_hash, unique_salt, sample_password)
    assert is_valid is True

def test_verify_password_incorrect(crypto_handler_fast, sample_password, unique_salt):
    stored_hash = crypto_handler_fast.hash_password(sample_password, unique_salt)
    wrong_password = "Пароль"
    is_valid = crypto_handler_fast.verify_password(stored_hash, unique_salt, wrong_password)
    assert is_valid is False

def test_verify_password_invalid_hash_type(crypto_handler_fast, sample_password, unique_salt):
    is_valid = crypto_handler_fast.verify_password("Строка, а не хеш", unique_salt, sample_password)
    assert is_valid is False

def test_derive_fernet_key_returns_bytes(crypto_handler_fast, sample_password, unique_salt):
    fernet_key = crypto_handler_fast.derive_fernet_key(sample_password, unique_salt)
    assert isinstance(fernet_key, bytes)
    try:
        decoded_key = base64.urlsafe_b64decode(fernet_key)
        assert len(decoded_key) == crypto_handler_fast._FERNET_KEY_LENGTH
    except Exception:
        pytest.fail("Сгенерированный Фернет ключ не валидный base64 или имеет не правильную длину.")

def test_encrypt_decrypt_data_cycle(crypto_handler_fast, sample_password, sample_data, unique_salt):
    fernet_key = crypto_handler_fast.derive_fernet_key(sample_password, unique_salt)
    encrypted = crypto_handler_fast.encrypt_data(sample_data, fernet_key)
    assert encrypted is not None
    assert isinstance(encrypted, bytes)
    assert encrypted != sample_data

    decrypted = crypto_handler_fast.decrypt_data(encrypted, fernet_key)
    assert decrypted is not None
    assert isinstance(decrypted, bytes)
    assert decrypted == sample_data

def test_decrypt_data_invalid_token(crypto_handler_fast, sample_password, sample_data, unique_salt):
    fernet_key = crypto_handler_fast.derive_fernet_key(sample_password, unique_salt)
    invalid_encrypted_data = os.urandom(50)
    decpypted = crypto_handler_fast.decrypt_data(invalid_encrypted_data, fernet_key)
    assert decpypted is None

def test_decrypt_data_wrong_key(crypto_handler_fast, sample_password, sample_data, unique_salt):
    different_salt = crypto_handler_fast.get_salt()
    fernet_key = crypto_handler_fast.derive_fernet_key(sample_password, unique_salt)
    def_fernet_key = crypto_handler_fast.derive_fernet_key(sample_password, different_salt)

    encrypted = crypto_handler_fast.encrypt_data(sample_data, fernet_key) # Шифруем правильным ключом
    assert encrypted is not None

    decrypted = crypto_handler_fast.decrypt_data(encrypted, def_fernet_key) # Дешифруем НЕПРАВИЛЬНЫМ ключом
    assert decrypted is None







