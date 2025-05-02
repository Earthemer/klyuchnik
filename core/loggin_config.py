import logging
import os
from logging.handlers import RotatingFileHandler
from functools import wraps


def setup_logging() ->None:
    """Настраивает глобальную конфигурацию логирования для приложения."""
    log_level_name = os.getenv('LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    log_file = os.getenv('LOG_FILE', 'logs/klychnik.log')
    log_dir = os.path.dirname(log_file)

    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError as e:
            logging.error(f"Не удалось создать директорию для логов {log_dir}: {e}")
            log_file = None


    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)")

    consol_handler = logging.StreamHandler()
    consol_handler.setLevel(logging.INFO if log_level_name != 'DEBUG' else logging.DEBUG)
    consol_handler.setFormatter(formatter)
    root_logger.addHandler(consol_handler)

    if log_file:
        try:
            max_log_size = 10 * 1024 * 1024
            backup_count = 5
            file_handler = RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=backup_count, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            root_logger.error(f"Не удалось настроить файловый логгер для {log_file}: {e}")

    root_logger.info(f"Настройка логирования завершена. Уровень: {log_level_name}. Файл: {log_file}")

def log_error(func):
    """Декоратор для автоматического логирования исключений, возникших в функции. Использует логгер с именем, специфичным для декорируемой функции."""
    logger_name = f"{func.__module__}.{func.__name__}"
    func_logger = logging.getLogger(logger_name)

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Логируем ошибку с подробным traceback'ом
            # Используем предсозданный func_logger
            func_logger.error(f"Исключение в функции {func.__name__}", exc_info=True)
            raise
    return wrapper


