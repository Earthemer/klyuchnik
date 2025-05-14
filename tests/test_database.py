import pytest
import pytest_asyncio
import os
import asyncio
from dotenv import load_dotenv

from core.database import AsyncDatabaseManager
from core.utils import get_int_env, get_str_env
from core.exceptions import (
    UserNotFoundError,
    DuplicateUserError,
    EntryNotFoundError,
    DatabaseQueryError,
    DatabaseConnectionError
)

load_dotenv()


# Переопределяем event_loop с областью видимости session
@pytest_asyncio.fixture(scope='session')
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# создаем фикстуры DSN не меняется в течение сессии
@pytest_asyncio.fixture(scope='session')
def db_dsn_test() -> str:
    host = get_str_env('TEST_DB_HOST', 'localhost')
    port = get_int_env('TEST_DB_PORT', 5432)
    user = get_str_env('TEST_DB_USER', 'default_user')
    password = get_str_env('TEST_DB_PASSWORD', '')
    dbname = get_str_env('TEST_DB_NAME', 'klychnik_test_db')
    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


# Фикстура для менеджера базы данных и создания/удаления таблиц один раз за сессию
@pytest_asyncio.fixture(scope='session')
async def db_manager_session(db_dsn_test: str, event_loop):
    manager = AsyncDatabaseManager(dsn=db_dsn_test, min_pool_size=1, max_pool_size=2)
    await manager.connect()

    try:
        async with manager._pool.acquire() as conn:
            await conn.execute("DROP TABLE IF EXISTS password_entries CASCADE;")
            await conn.execute("DROP TABLE IF EXISTS users CASCADE;")

            schema_file_path = os.path.join(os.path.dirname(__file__), '..', 'schema.sql')
            with open(schema_file_path, 'r', encoding='utf-8') as f:
                schema_sql = f.read()
            await conn.execute(schema_sql)
            print("\nТестовые таблицы успешно созданы.")
    except Exception as e:
        print(f"\n[SETUP ERROR] Ошибка при создании тестовых таблиц: {e}")

    yield manager

    try:
        async with manager._pool.acquire() as conn_teardown:
            await conn_teardown.execute("DROP TABLE IF EXISTS password_entries CASCADE;")
            await conn_teardown.execute("DROP TABLE IF EXISTS users CASCADE;")
        print("Тестовые таблицы успешно удалены после сессии.")
    except Exception as e:
        print(f"\n[TEARDOWN ERROR] Ошибка при удалении тестовых таблиц после сессии: {e}")

    await manager.disconnect()
    print("Соединение с БД закрыто после сессии.")


# Фикстура для запуска изолированных тестов
@pytest_asyncio.fixture(scope='function')
async def db_start_testing(db_manager_session: AsyncDatabaseManager):
    try:
        async with db_manager_session._pool.acquire() as conn:
            await conn.execute("TRUNCATE TABLE password_entries RESTART IDENTITY CASCADE;")
            await conn.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE;")
    except Exception as e:
        print(f"\nОшибка при очистке таблиц перед тестом: {e}")
        raise
    return db_manager_session


# утилида создание id\user
async def create_user_for_test(
        manager: AsyncDatabaseManager,
        login: str = 'test_user',
        password_hash: bytes = b"test_hash",
        salt: bytes = b"test_salt"
) -> int:
    return await manager.create_user(login, password_hash, salt)


# --- Тесты для AsyncDatabaseManager ---

@pytest.mark.asyncio
async def test_create_user_success(db_start_testing: AsyncDatabaseManager):
    manager = db_start_testing
    user_id = await create_user_for_test(manager)
    assert isinstance(user_id, int)
    assert user_id > 0


@pytest.mark.asyncio
async def test_create_user_duplicate(db_start_testing: AsyncDatabaseManager):
    """Тест создания пользователя с уже существующим логином."""
    user_id = await create_user_for_test(db_start_testing)
    with pytest.raises(DuplicateUserError):
        await create_user_for_test(db_start_testing)


@pytest.mark.asyncio
async def test_get_user_credentials_success(db_start_testing: AsyncDatabaseManager):
    manager = db_start_testing
    user_id = await create_user_for_test(manager)
    creds = await manager.get_user_credentials('test_user')
    assert creds is not None
    assert creds[0] == user_id  # Проверяем, что ID совпадает
    assert creds[1] == b"test_hash"
    assert creds[2] == b"test_salt"


@pytest.mark.asyncio
async def test_get_user_credentials_not_found(db_start_testing: AsyncDatabaseManager):
    manager = db_start_testing
    with pytest.raises(UserNotFoundError):
        await manager.get_user_credentials("non_existent_user")


@pytest.mark.asyncio
async def test_add_entry_success(db_start_testing: AsyncDatabaseManager):
    manager = db_start_testing
    user_id = await create_user_for_test(manager)
    entry_id = await manager.add_entry(user_id, 'Service_name', 'username', b'enc_pass', b'enc_url', b'enc_notes')
    assert isinstance(entry_id, int)
    assert entry_id > 0

@pytest.mark.asyncio
async def test_add_entry_fk_violation(db_start_testing: AsyncDatabaseManager):
    """Попытка добавить запись для несуществующего пользователя (нарушение внешнего ключа)."""
    with pytest.raises(DatabaseQueryError):
        await db_start_testing.add_entry(
            user_id=9999,  # несуществующий ID
            service_name="FakeService",
            username="ghost",
            encrypted_password=b"pass",
            encrypted_url=None,
            encrypted_notes=None
        )


@pytest.mark.asyncio
async def test_get_entries_list_empty(db_start_testing: AsyncDatabaseManager):
    """Пустой список записей у нового пользователя."""
    user_id = await create_user_for_test(db_start_testing)
    entries = await db_start_testing.get_entries_list(user_id)
    assert isinstance(entries, list)
    assert len(entries) == 0


@pytest.mark.asyncio
async def test_get_entries_list_with_data(db_start_testing: AsyncDatabaseManager):
    """Получение списка записей у пользователя с одной записью."""
    user_id = await create_user_for_test(db_start_testing)
    entry_id = await db_start_testing.add_entry(
        user_id=user_id,
        service_name="TestService",
        username="tester",
        encrypted_password=b"secret",
        encrypted_url=b"url",
        encrypted_notes=None
    )
    entries = await db_start_testing.get_entries_list(user_id)
    assert isinstance(entries, list)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["id"] == entry_id
    assert entry["service_name"] == "TestService"
    assert entry["username"] == "tester"


@pytest.mark.asyncio
async def test_get_entry_details_success(db_start_testing: AsyncDatabaseManager):
    """Получение детальной информации по записи, принадлежащей пользователю."""
    user_id = await create_user_for_test(db_start_testing)
    entry_id = await db_start_testing.add_entry(
        user_id=user_id,
        service_name="DeepService",
        username="deep_user",
        encrypted_password=b"deep_pw",
        encrypted_url=b"deep_url",
        encrypted_notes=b"note"
    )
    details = await db_start_testing.get_entry_details(entry_id, user_id)
    assert details["id"] == entry_id
    assert details["user_id"] == user_id
    assert details["service_name"] == "DeepService"
    assert details["username"] == "deep_user"


@pytest.mark.asyncio
async def test_get_entry_details_not_found_or_wrong_user(db_start_testing: AsyncDatabaseManager):
    """Запись не найдена или принадлежит другому пользователю."""
    user1_id = await create_user_for_test(db_start_testing, login='u1')
    user2_id = await create_user_for_test(db_start_testing, login='u2')
    entry_id = await db_start_testing.add_entry(
        user_id=user1_id,
        service_name="HiddenService",
        username="hider",
        encrypted_password=b"123",
        encrypted_url=None,
        encrypted_notes=None
    )

    # Попытка получить запись другим пользователем
    with pytest.raises(EntryNotFoundError):
        await db_start_testing.get_entry_details(entry_id, user2_id)

    # Попытка получить несуществующую запись
    with pytest.raises(EntryNotFoundError):
        await db_start_testing.get_entry_details(99999, user1_id)


@pytest.mark.asyncio
async def test_delete_entry_success(db_start_testing: AsyncDatabaseManager):
    """Удаление записи успешно."""
    user_id = await create_user_for_test(db_start_testing)
    entry_id = await db_start_testing.add_entry(
        user_id=user_id,
        service_name="DeleteMe",
        username="doomed",
        encrypted_password=b"123",
        encrypted_url=None,
        encrypted_notes=None
    )
    result = await db_start_testing.delete_entry(entry_id, user_id)
    assert result is True


@pytest.mark.asyncio
async def test_delete_entry_not_found_or_wrong_user(db_start_testing: AsyncDatabaseManager):
    """Попытка удалить запись, которая не существует или чужая."""
    user1_id = await create_user_for_test(db_start_testing, login="a")
    user2_id = await create_user_for_test(db_start_testing, login="b")
    entry_id = await db_start_testing.add_entry(
        user_id=user1_id,
        service_name="OwnedByA",
        username="ownera",
        encrypted_password=b"enc",
        encrypted_url=None,
        encrypted_notes=None
    )

    # Попытка удалить чужую запись
    with pytest.raises(EntryNotFoundError):
        await db_start_testing.delete_entry(entry_id, user2_id)

    # Попытка удалить несуществующую запись
    with pytest.raises(EntryNotFoundError):
        await db_start_testing.delete_entry(99999, user1_id)
