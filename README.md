# Klychnik Password Manager

## Description

"Klychnik" is a secure, local, asynchronous command-line password manager being developed in Python. The project aims to create a reliable and simple tool for managing passwords, with special attention to data storage security and best development practices.

## Key Features (MVP - Minimum Viable Product)

*   **Local Storage:** Data is stored locally in a PostgreSQL database. For binary data security, such as hashes, salts, and ciphertext, the `BYTEA` data type is used.
*   **Master Password:** Access to the storage is protected by a unique user master password.
*   **Robust Security:**
    *   Master password hashing is implemented using the PBKDF2HMAC algorithm with a unique cryptographic salt for each user.
    *   All sensitive entry data (service passwords, URLs, notes) are subjected to symmetric encryption using Fernet (AES).
    *   The encryption key is generated based on the master password and user salt upon each login and stored exclusively in operative memory during an active session.
*   **Core Operations (CRUD):** Supports operations for adding, listing entries (displaying only non-sensitive fields), retrieving full entry information (with "on-the-fly" decryption), and deleting entries. Managed data includes: Service Name, Service Username, Service Password, URL, and Notes.
*   **Command-Line Interface (CLI):** Interaction with the application is done via terminal commands implemented using the `Typer` library.
*   **Asynchronicity:** All interactions with the PostgreSQL database are performed asynchronously using the `asyncpg` library to improve performance.
*   **Configuration:** Key application parameters (database settings, cryptographic parameters, logging level) are externalized to `.env` files for flexible configuration.

## Technology Stack

*   **Language:** Python 3.12+
*   **Asynchronicity:** `asyncio`, `asyncpg`
*   **Database:** PostgreSQL (with active use of `BYTEA` type)
*   **Cryptography:** `cryptography` library (PBKDF2HMAC, Fernet)
*   **Command-Line Interface (CLI):** `Typer`
*   **Configuration Management:** `python-dotenv`
*   **Logging:** Standard `logging` module

## Status

The project is under active development.