import pytest
import os
import psycopg2
from typing import Generator
from core.database import DatabaseManager
from core.utils import get_int_env, get_str_env
from core.exceptions import (
    UserNotFoundError,
    DuplicateUserError,
    EntryNotFoundError,
    DatabaseQueryError
)


# Фискстуры:

@pytest.fixture(scope='session')
def db_dsn_test() -> str:
    """Формирует DSN для тестовой базы данных из переменной окружения."""
    host = get_str_env('TEST_DB_HOST', 'localhost')
    port = get_int_env('TEST_DB_PORT', 5432)
    user = get_str_env('TEST_DB_USER', 'postgres')
    password = get_str_env('TEST_DB_PASSWORD', "")
    dbname = get_str_env('TEST_DB_NAME', 'klychnik_test_db')
    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


@pytest.fixture(scope='session')
def db_manager_session_scoped(db_dsn_test: str) -> Generator[DatabaseManager, None, None]:
    """
    Фикстура один раз за сессию:
    - Создает экземпляр DatabaseManager.
    - Удаляет и создает таблицы в тестовой БД.
    - Предоставляет менеджер для использования.
    - Удаляет таблицы после всех тестов.
    """
    manager = DatabaseManager(dsn=db_dsn_test)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    try:
        with psycopg2.connect(db_dsn_test) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS password_entries CASCADE;")
                cur.execute("DROP TABLE IF EXISTS users CASCADE;")
                print("[DB SETUP] Создание таблиц по schema.sql...")
                schema_file_path = os.path.join(project_root, 'schema.sql')
                if not os.path.exists(schema_file_path):
                    raise FileNotFoundError(f"Файл schema.sql не найден по пути: {schema_file_path}")

                with open(schema_file_path, 'r', encoding='utf-8') as f:
                    schema_sql = f.read()
                cur.execute(schema_sql)
                print("[DB SETUP] Таблицы успешно созданы.")
    except psycopg2.Error as e:
        pytest.fail(f"Критическая ошибка при настройке тестовой БД (setup): {e}")

    yield manager

    try:
        with psycopg2.connect(db_dsn_test) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS password_entries CASCADE;")
                cur.execute("DROP TABLE IF EXISTS users CASCADE;")
                print("\n[DB TEARDOWN] Удаление таблиц...")
    except psycopg2.Error as e:
        print(f"Ошибка при очистке тестовой БД (teardown): {e}")
        pass


@pytest.fixture(scope='function')
def db_manager(db_manager_session_scoped: DatabaseManager) -> DatabaseManager:
    """
    Фикстура для каждого теста:
    - Очищает данные из таблиц (TRUNCATE) перед каждым тестом.
    - Предоставляет тот же экземпляр DatabaseManager.
    """
    manager = db_manager_session_scoped
    try:
        with psycopg2.connect(manager.dsn) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE password_entries RESTART IDENTITY CASCADE;")
                cur.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE;")
    except psycopg2.Error as e:
        pytest.fail(f"Ошибка при очистке данных таблиц перед тестом: {e}")
    return manager

# --- Вспомогательные функции ---
def create_test_user(
        manager: DatabaseManager,
        login: str = "testuser",
        password_hash: bytes = b"generic_hash",
        salt: bytes = b"generic_salt"
) -> int:
    return manager.create_user(login, password_hash, salt)

# --- Тесты для DatabaseManager ---

def test_create_user_success(db_manager: DatabaseManager):
    user_id = create_test_user(db_manager, login="new_user_sync")
    assert isinstance(user_id, int)
    assert user_id > 0
    creds = db_manager.get_user_credentials("new_user_sync")
    assert creds is not None
    assert creds[0] == user_id


def test_create_user_duplicate(db_manager: DatabaseManager):
    create_test_user(db_manager, login="duplicate_sync_user")
    with pytest.raises(DuplicateUserError):
        create_test_user(db_manager, login="duplicate_sync_user")


def test_get_user_credentials_success(db_manager: DatabaseManager):
    login = "cred_user_sync"
    phash = b"s_hash"
    salt = b"s_salt"
    user_id = create_test_user(db_manager, login=login, password_hash=phash, salt=salt)
    fetched_id, fetched_hash, fetched_salt = db_manager.get_user_credentials(login)
    assert fetched_id == user_id
    assert fetched_hash == phash
    assert fetched_salt == salt


def test_get_user_credentials_not_found(db_manager: DatabaseManager):
    with pytest.raises(UserNotFoundError):
        db_manager.get_user_credentials("no_such_user_sync")


def test_add_entry_success(db_manager: DatabaseManager):
    user_id = create_test_user(db_manager)
    entry_id = db_manager.add_entry(
        user_id=user_id,
        service_name="SyncService",
        username="sync_service_user",
        encrypted_password=b"s_enc_pass",
        encrypted_url=b"s_enc_url",
        encrypted_notes=b"s_enc_notes"
    )
    assert isinstance(entry_id, int)
    assert entry_id > 0
    details = db_manager.get_entry_details(entry_id, user_id)
    assert details is not None
    assert details['service_name'] == "SyncService"


def test_add_entry_fk_violation(db_manager: DatabaseManager):
    with pytest.raises(
            DatabaseQueryError) as excinfo:  # DatabaseManager выбрасывает DatabaseQueryError для ForeignKeyViolation
        db_manager.add_entry(99999, "OrphanS", "oS", b"p", None, None)
    assert "Нарушение внешнего ключа" in str(excinfo.value)


def test_get_entries_list_empty(db_manager: DatabaseManager):
    user_id = create_test_user(db_manager)
    entries = db_manager.get_entries_list(user_id)
    assert isinstance(entries, list)
    assert len(entries) == 0


def test_get_entries_list_with_data(db_manager: DatabaseManager):
    user_id = create_test_user(db_manager)
    db_manager.add_entry(user_id, "SyncS1", "u1s", b"p1s", None, None)
    db_manager.add_entry(user_id, "SyncS2", "u2s", b"p2s", None, None)
    entries = db_manager.get_entries_list(user_id)
    assert len(entries) == 2
    # Проверка порядка, если он важен (ORDER BY service_name)
    assert entries[0]['service_name'] == "SyncS1"
    assert entries[1]['service_name'] == "SyncS2"


def test_get_entry_details_success(db_manager: DatabaseManager):
    user_id = create_test_user(db_manager)
    entry_id = db_manager.add_entry(user_id, "DetailSyncS", "ds_user", b"ds_pass", None, None)
    details = db_manager.get_entry_details(entry_id, user_id)
    assert details is not None
    assert details['id'] == entry_id
    assert details['service_name'] == "DetailSyncS"


def test_get_entry_details_not_found(db_manager: DatabaseManager):
    user_id = create_test_user(db_manager)
    with pytest.raises(EntryNotFoundError):
        db_manager.get_entry_details(99999, user_id)


def test_get_entry_details_wrong_user(db_manager: DatabaseManager):
    user1_id = create_test_user(db_manager, login="sync_user1_details")
    user2_id = create_test_user(db_manager, login="sync_user2_details")
    entry_id_u1 = db_manager.add_entry(user1_id, "ServiceU1SyncDetails", "u1sd", b"p1sd", None, None)
    with pytest.raises(EntryNotFoundError):
        db_manager.get_entry_details(entry_id_u1, user2_id)


def test_delete_entry_success(db_manager: DatabaseManager):
    user_id = create_test_user(db_manager)
    entry_id = db_manager.add_entry(user_id, "ToDeleteSync", "del_usync", b"del_psync", None, None)
    delete_status = db_manager.delete_entry(entry_id, user_id)
    assert delete_status is True
    with pytest.raises(EntryNotFoundError):
        db_manager.get_entry_details(entry_id, user_id)


def test_delete_entry_not_found(db_manager: DatabaseManager):
    user_id = create_test_user(db_manager)
    with pytest.raises(EntryNotFoundError):
        db_manager.delete_entry(88888, user_id)


def test_delete_entry_wrong_user(db_manager: DatabaseManager):
    user1_id = create_test_user(db_manager, login="owner_sync_del")
    user2_id = create_test_user(db_manager, login="hacker_sync_del")
    entry_id_owner = db_manager.add_entry(user1_id, "OwnedSSyncDel", "os_ud", b"os_pd", None, None)
    with pytest.raises(EntryNotFoundError):
        db_manager.delete_entry(entry_id_owner, user2_id)
    # Убедимся, что запись не была удалена
    details = db_manager.get_entry_details(entry_id_owner, user1_id)
    assert details is not None


