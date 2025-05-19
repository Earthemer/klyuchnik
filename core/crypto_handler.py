import os
import base64
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidKey
from core.logging_config import log_error

logger = logging.getLogger(__name__)

class CryptoHandler:
    """Отвечает за хеширование, верификацию паролей и шифрование данных."""

    #Определяем константы на уровне класса, после юзаем их в __init__

    _DEFAULT_SALT_SIZE = 16
    _FERNET_KEY_LENGTH = 32
    _HASH_ALGORITHM = hashes.SHA256()

    def __init__(self, iterations: int):
        self.iterations = iterations
        if self.iterations < 100000:
            logger.warning(f"Инициализация CryptoHandler с потенциально низким числом итераций PBKDF2: {self.iterations}")
        logger.info(f"CryptoHandler инициализирован. Итераций: {self.iterations}, Размер соли: {self._DEFAULT_SALT_SIZE}")

    #Соль.
    @log_error
    def get_salt(self)-> bytes:
        salt_size = self._DEFAULT_SALT_SIZE
        logger.debug(f"Генерация соли размером {salt_size} байт.")
        return os.urandom(salt_size)

    #Хешируем в байтах.
    @log_error
    def hash_password(self, password: str, salt: bytes)-> bytes:
        logger.debug("Хеширование пароля...")
        password_bytes = password.encode('utf-8')
        if not isinstance(salt, bytes) or len(salt) != self._DEFAULT_SALT_SIZE:
            logger.error(f"Некорректный тип или размер соли ({len(salt) if isinstance(salt, bytes) else type(salt)}).")
            raise ValueError("Некорректная соль для хеширования.")

        kdf_hasher = PBKDF2HMAC(
            algorithm=self._HASH_ALGORITHM,
            length=self._HASH_ALGORITHM.digest_size,
            salt=salt,
            iterations=self.iterations,
        )
        hashed_password = kdf_hasher.derive(password_bytes)
        logger.info("Пароль успешно хеширован.")
        return hashed_password


    #Веретификация пароля
    @log_error
    def verify_password(self, stored_hash: bytes, salt: bytes, provided_password: str)-> bool:
        logger.debug("Проверка пароля...")
        provided_password_bytes = provided_password.encode('utf-8')

        if not isinstance(stored_hash, bytes) or not isinstance(salt, bytes):
            logger.error("Ошибка верификации: хеш и соль должны быть bytes.")
            return False

        kdf_verifier = PBKDF2HMAC(
            algorithm=self._HASH_ALGORITHM,
            length=len(stored_hash),
            salt=salt,
            iterations=self.iterations,
        )

        try:
            kdf_verifier.verify(provided_password_bytes, stored_hash)
            logger.info("Проверка пароля прошла успешно.")
            return True
        except InvalidKey:
            logger.warning("Проверка пароля не удалась: неверный пароль.")
            return False
        except Exception as e:
            logger.error(f"Неожиданная ошибка при проверке (verify): {e}", exc_info=True)
            return False

    #Генерируем fernet для шифрования
    @log_error
    def derive_fernet_key(self, master_password: str, salt: bytes) -> bytes:
        logger.debug("Генерация ключа Fernet...")
        password_bytes = master_password.encode('utf-8')
        if not isinstance(salt, bytes):
            logger.error("Некорректный тип соли для генерации ключа Fernet.")
            raise ValueError("Некорректная соль для генерации ключа.")
        kdf_key_gen = PBKDF2HMAC(
            algorithm=self._HASH_ALGORITHM,
            length=self._FERNET_KEY_LENGTH,
            salt=salt,
            iterations=self.iterations,
        )
        derive_key_bytes = kdf_key_gen.derive(password_bytes)
        fernet_key = base64.urlsafe_b64encode(derive_key_bytes)
        logger.info("Ключ Fernet успешно сгенерирован (возвращены base64 байты).")
        return fernet_key

    #Шифрование с использованием fernet
    @log_error
    def encrypt_data(self, data: bytes, fernet_key: bytes) -> bytes | None:
        logger.debug("Шифровании данных...")
        if not isinstance(data, bytes) or not isinstance(fernet_key, bytes):
            logger.error("Типы данных для шифрования или ключа некорректны.")
            return None

        try:
            f = Fernet(fernet_key)
            encrypted_data = f.encrypt(data)
            logger.info("Данные успешно зашифрованы.")
            return encrypted_data
        except Exception as e:
            logger.error(f"Ошибка при шифровании данных: {e}", exc_info=True)
            return None

    #Дешифровка
    @log_error
    def decrypt_data(self, encrypted_data: bytes, fernet_key: bytes) -> bytes | None:
        logger.debug("Дешифрование данных...")
        if not isinstance(encrypted_data, bytes) or not isinstance(fernet_key, bytes):
            logger.error("Ошибка дешифровки: неверный тип данных или ключа.")
            return None

        try:
            f = Fernet(fernet_key)
            decrypted_data = f.decrypt(encrypted_data)
            logger.info("Данные успешно дешифрованы.")
            return decrypted_data
        except InvalidToken:
            logger.warning("Ошибка дешифровки: InvalidToken (ключ/данные).")
            return None
        except Exception as e:
            logger.error(f"Неожиданная ошибка при дешифровке: {e}", exc_info=True)
            return None






















