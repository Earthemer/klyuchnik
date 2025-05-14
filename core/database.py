import logging
import asyncpg
from asyncpg.pool import Pool
from core.exceptions import DatabaseConnectionError, UserNotFoundError, DuplicateUserError, EntryNotFoundError, \
    DatabaseQueryError
from typing import Any

logger = logging.getLogger(__name__)


# Асинхронный менеджер для взаимодействия с бд PostgreSQL/ управляет пулом соединения и выполняем CRUD - операции
class AsyncDatabaseManager:
    def __init__(self, dsn: str, min_pool_size: int = 1, max_pool_size: int = 10):
        self._dsn = dsn
        self._min_pool_size = min_pool_size
        self._max_pool_size = max_pool_size
        self._pool: Pool | None = None
        logger.info(
            f"DatabaseManager инициализирован. DSN: {dsn[:dsn.find('@')] + '@*****' if '@' in dsn else dsn}")  # Логируем DSN без пароля

    async def connect(self):
        if self._pool is None:
            try:
                self._pool = await asyncpg.create_pool(
                    dsn=self._dsn,
                    min_size=self._min_pool_size,
                    max_size=self._max_pool_size
                )
                logger.info(f"Пул соединений PostgreSQL ({self._min_pool_size}-{self._max_pool_size}) успешно создан.")

                async with self._pool.acquire() as conn:
                    val = await conn.fetchval("SELECT 1")
                    if val == 1:
                        logger.info("Проверка соединения с БД прошла успешно.")
                    else:
                        logger.warning("Проверка соединения с БД не удалась.")
                        raise DatabaseConnectionError("Не удалось верифицировать соединение с БД.")
            except (asyncpg.PostgresError, OSError) as e:
                logger.critical(f"Не удалось создать пул соединений PostgreSQL: {e}", exc_info=True)
                raise DatabaseConnectionError("Не удалось подключится к база данных") from e
        else:
            logger.warning("Пул соединений уже создан.")

    async def disconnect(self):
        if self._pool:
            try:
                await self._pool.close()
                logger.info("Пул соединений PostgreSQL успешно закрыт.")
            except Exception as e:
                logger.error(f"Ошибка при закрытии пула соединений: {e}", exc_info=True)
            finally:
                self._pool = None
        else:
            logger.debug("Пул неактивен — закрытие не требуется.")

    async def _execute(self, query: str, *args: Any, fetch_all: bool = False, fetch_val: bool = False,
                       fetch_one: bool = False) -> asyncpg.Record | list[asyncpg.Record] | str | Any | None:
        if self._pool is None:
            logger.error("Ошибка выполнения запроса: Пул соединений не инициализирован.")
            raise DatabaseConnectionError("Пул соединений не инициализирован.")

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                try:
                    log_args = tuple(
                        str(arg)[:50] + '...' if isinstance(arg, (str, bytes)) and len(arg) > 50 else arg for arg in
                        args)
                    if fetch_val:
                        logger.debug(f"Выполнение fetchval. Args: {log_args}")
                        return await conn.fetchval(query, *args)
                    elif fetch_one:
                        logger.debug(f"Выполнение fetchrow. Args: {log_args}")
                        return await conn.fetchrow(query, *args)
                    elif fetch_all:
                        logger.debug(f"Выполнение fetch. Args: {log_args}")
                        return await conn.fetch(query, *args)
                    else:
                        logger.debug(f"Выполнение execute. Args: {log_args}")
                        status = await conn.execute(query, *args)
                        logger.debug(f"Запрос выполнен. Статус: {status}")
                        return status
                except asyncpg.PostgresError as e:
                    logger.error(f"Непредвиденная ошибка при запросе к БД. Ошибка: {e}", exc_info=True)
                    raise DatabaseQueryError(f"Непредвиденная ошибка при работе с БД: {e}") from e

    async def create_user(self, login: str, master_password_hash: bytes, salt: bytes) -> int:
        sql = """
               INSERT INTO users (login, master_password_hash, salt)
               VALUES ($1, $2, $3)
               RETURNING id;
           """
        try:
            user_id = await self._execute(sql, login, master_password_hash, salt, fetch_val=True)

            if user_id is None:
                logger.error(f"Создание пользователя '{login}' не вернуло ID от fetchval.")
                raise DatabaseQueryError("Не удалось получить ID пользователя после создания.")

            if not isinstance(user_id, int):
                logger.error(f"Создание пользователя '{login}' вернуло ID не типа int. Получено: {type(user_id)}.")
                raise DatabaseQueryError(f"Внутренняя ошибка: ID пользователя имеет неверный тип ({type(user_id)}).")

            logger.info(f"Пользователь '{login}' успешно создан с ID {user_id}.")
            return user_id

        except DatabaseQueryError as e:
            if isinstance(e.__cause__, asyncpg.exceptions.UniqueViolationError):
                logger.warning(f"Попытка создать дублирующегося пользователя '{login}'.")
                raise DuplicateUserError(f"Пользователь с логином '{login}' уже существует.") from e.__cause__
            else:
                logger.error(f"Ошибка БД при создании пользователя '{login}': {e}")
                raise

    async def get_user_credentials(self, login: str) -> tuple[int, bytes, bytes]:
        sql = "SELECT id, master_password_hash, salt FROM users WHERE login = $1;"
        record = await self._execute(sql, login, fetch_one=True)
        if record:
            return record['id'], record['master_password_hash'], record['salt']
        else:
            logger.warning(f"Пользователь с логином '{login}' не найден при попытке получить учетные данные.")
            raise UserNotFoundError(f"Пользователь '{login}' не найден.")

    async def add_entry(self, user_id: int, service_name: str, username: str, encrypted_password: bytes,
                        encrypted_url: bytes | None, encrypted_notes: bytes | None) -> int:
        sql = """
            INSERT INTO password_entries (user_id, service_name, username, encrypted_password, encrypted_url, encrypted_notes)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id;
        """
        try:
            entry_id = await self._execute(
                sql, user_id, service_name, username,
                encrypted_password, encrypted_url, encrypted_notes,
                fetch_val=True
            )
            if entry_id is None:
                logger.error(f"Добавление записи для user_id={user_id} не вернуло ID.")
                raise DatabaseQueryError("Не удалось получить ID записи после добавления.")
            logger.info(
                f"Запись ID {entry_id} (сервис: {service_name}) для пользователя ID {user_id} успешно добавлена.")
            return entry_id
        except asyncpg.exceptions.ForeignKeyViolationError as e:
            logger.error(
                f"Ошибка внешнего ключа при добавлении записи для user_id={user_id}. Возможно, пользователь не существует.",
                exc_info=True)
            raise DatabaseQueryError(
                f"Ошибка целостности данных: не удалось добавить запись из-за неверного ID пользователя ({user_id}).") from e

    async def get_entries_list(self, user_id: int) -> list[dict[str, Any]]:
        sql = "SELECT id, service_name, username FROM password_entries WHERE user_id = $1 ORDER BY service_name, username;"
        records = await self._execute(sql, user_id, fetch_all=True)
        return [dict(record) for record in records]

    async def get_entry_details(self, entry_id: int, user_id: int) -> dict[str, Any]:
        sql = """
            SELECT id, user_id, service_name, username, encrypted_password,
                   encrypted_url, encrypted_notes FROM password_entries
            WHERE id = $1 AND user_id = $2;
        """
        record = await self._execute(sql, entry_id, user_id, fetch_one=True)
        if record:
            return dict(record)
        else:
            logger.warning(f"Запись ID {entry_id} для пользователя ID {user_id} не найдена.")
            raise EntryNotFoundError(f"Запись с ID {entry_id} не найдена или не принадлежит пользователю.")

    async def delete_entry(self, entry_id: int, user_id: int) -> bool:
        sql = "DELETE FROM password_entries WHERE id = $1 AND user_id = $2;"
        status_str = await self._execute(sql, entry_id, user_id)

        if isinstance(status_str, str) and status_str.startswith("DELETE"):
            _, _, count = status_str.partition(" ")
            deleted_count = int(count)
            if deleted_count == 1:
                logger.info(f"Запись ID {entry_id} пользователя ID {user_id} успешно удалена.")
                return True
            elif deleted_count == 0:
                logger.warning(f"Попытка удалить несуществующую или чужую запись: ID {entry_id} для user ID {user_id}.")
                raise EntryNotFoundError(
                    f"Запись с ID {entry_id} не найдена для удаления или не принадлежит пользователю.")
            else:  # deleted_count > 1 (невозможно с PK) или < 0 (невозможно)
                logger.error(
                    f"Неожиданное количество удаленных строк ({deleted_count}) для записи ID {entry_id}, user ID {user_id}.")
                raise DatabaseQueryError("Операция удаления вернула неожиданный результат.")
        else:
            logger.error(f"Неожиданный статус от операции DELETE: {status_str}")
            raise DatabaseQueryError("Неожиданный результат операции удаления.")
