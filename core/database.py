import logging
import psycopg2
from psycopg2.extras import DictCursor
from core.exceptions import UniqueViolation, ForeignKeyViolation
from typing import Any

from core.exceptions import (
    DatabaseConnectionError,
    UserNotFoundError,
    DuplicateUserError,
    EntryNotFoundError,
    DatabaseQueryError
)

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self, dsn: str):
        self._dsn = dsn
        logger.info(f"DatabaseManager инициализирован.")

    @property
    def dsn(self) -> str:
        return self._dsn

    def _execute(
            self,
            query: str,
            params: tuple | None = None,
            fetch_one: bool = False,
            fetch_all: bool = False
    ) -> Any | None:

        if fetch_one and fetch_all:
            raise ValueError("fetch_one и fetch_all взаимоисключающие.")

        logger.debug(f"Попытка выполнить SQL: {query[:100]}... с параметрами: {params}")
        try:
            with psycopg2.connect(dsn=self.dsn) as conn:
                conn.autocommit = True
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute(query, params or ())
                    affected_row_count = cur.rowcount

                    if fetch_one:
                        result = cur.fetchone()
                        result = dict(result) if result else None
                        logger.debug(f"Fetch one результат: {result}")
                        return result

                    if fetch_all:
                        results = cur.fetchall()
                        result = [dict(row) for row in results]
                        logger.debug(f"Fetch all результат (количество): {len(result)}")
                        return result

                    return affected_row_count

        except UniqueViolation as e:
            raise DuplicateUserError("Нарушение уникальности.") from e
        except ForeignKeyViolation as e:
            raise DatabaseQueryError("Нарушение внешнего ключа.") from e
        except psycopg2.OperationalError as e:
            raise DatabaseConnectionError("Ошибка подключения к БД.") from e
        except psycopg2.Error as e:
            raise DatabaseQueryError("Ошибка базы данных.") from e

    def create_user(self, login: str, master_password_hash: bytes, salt: bytes) -> int:
        sql = """
            INSERT INTO users (login, master_password_hash, salt)
            VALUES (%s, %s, %s)
            RETURNING id;
        """
        result = self._execute(sql, (login, master_password_hash, salt), fetch_one=True)

        if not result or 'id' not in result:
            logger.error(f"Создание пользователя '{login}' не вернуло ID. Результат: {result}")
            raise DatabaseQueryError("Не удалось получить ID пользователя после создания.")

        user_id = result['id']
        if not isinstance(user_id, int):
            logger.error(f"Создание пользователя '{login}' вернуло ID не int: {type(user_id)}")
            raise DatabaseQueryError("Неверный тип ID пользователя.")

        logger.info(f"Пользователь '{login}' создан с ID {user_id}.")
        return user_id

    def get_user_credentials(self, login: str) -> tuple[int, bytes, bytes]:
        sql = """
            SELECT id, master_password_hash, salt
            FROM users
            WHERE login = %s;
        """
        result = self._execute(sql, (login,), fetch_one=True)

        if not result:
            logger.warning(f"Учетные данные пользователя '{login}' не найдены.")
            raise UserNotFoundError(f"Пользователь '{login}' не найден.")

        user_id = result['id']
        password_hash = bytes(result['master_password_hash'])
        salt = bytes(result['salt'])
        return user_id, password_hash, salt

    def add_entry(
            self,
            user_id: int,
            service_name: str,
            username: str,
            encrypted_password: bytes,
            encrypted_url: bytes | None,
            encrypted_notes: bytes | None
    ) -> int:
        sql = """
            INSERT INTO password_entries
            (user_id, service_name, username, encrypted_password, encrypted_url, encrypted_notes)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id;
        """
        params = (user_id, service_name, username, encrypted_password, encrypted_url, encrypted_notes)
        result = self._execute(sql, params, fetch_one=True)

        if not result or 'id' not in result:
            logger.error(f"Добавление записи не вернуло ID. Результат: {result}")
            raise DatabaseQueryError("Не удалось получить ID записи после добавления.")

        entry_id = result['id']
        logger.info(f"Запись ID {entry_id} для пользователя {user_id} добавлена (сервис: '{service_name}').")
        return entry_id

    def get_entries_list(self, user_id) -> list[dict]:
        sql = """
            SELECT id, service_name, username
            FROM password_entries
            WHERE user_id = %s
            ORDER BY service_name, username;
        """
        result = self._execute(sql, (user_id,), fetch_all=True)
        return result or []

    def get_entry_details(self, entry_id: int, user_id: int) -> dict:
        sql = """
            SELECT id, user_id, service_name, username, encrypted_password, encrypted_url, encrypted_notes
            FROM password_entries
            WHERE id = %s AND user_id = %s;
        """
        result = self._execute(sql, (entry_id, user_id), fetch_one=True)

        if not result:
            logger.warning(f"Запись ID {entry_id} не найдена для пользователя {user_id}.")
            raise EntryNotFoundError(f"Запись ID {entry_id} не найдена или не принадлежит пользователю.")

        return result

    def delete_entry(self, entry_id: int, user_id: int) -> bool:
        sql = """
            DELETE FROM password_entries
            WHERE id = %s AND user_id = %s;
        """
        affected_rows = self._execute(sql, (entry_id, user_id))

        if affected_rows == 1:
            logger.info(f"Запись ID {entry_id} пользователя {user_id} удалена.")
            return True

        if affected_rows == 0:
            logger.warning(
                f"Удаление неудачно: запись ID {entry_id} не найдена или не принадлежит пользователю {user_id}.")
            raise EntryNotFoundError(f"Запись ID {entry_id} не найдена или не принадлежит пользователю.")

        logger.error(f"Удаление записи ID {entry_id} вернуло неожиданное количество строк: {affected_rows}.")
        raise DatabaseQueryError(f"Операция удаления вернула некорректное число строк: {affected_rows}.")
