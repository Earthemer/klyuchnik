class DatabaseError(Exception):
    # База для ошибок
    pass


class UserNotFoundError(DatabaseError):
    # Пользователь не найден
    pass


class DuplicateUserError(DatabaseError):
    # Пользователь с таким именем уже существует
    pass


class EntryNotFoundError(DatabaseError):
    # Запись не найдена
    pass

class DatabaseConnectionError(DatabaseError):
    # Ошибка соединения
    pass

class DatabaseQueryError(DatabaseError):
    # Ошибка выполнения запроса
    pass
