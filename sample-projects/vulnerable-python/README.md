# Vulnerable Multi-File Python Sample Application

This project is a multi-tier Python application designed to demonstrate static analysis, cross-file vulnerability propagation, code slop detection, and logic gap hunting.

## Architecture

- `frontend/login.js`: Client-side input triggering search queries.
- `backend/routes.py`: API endpoint receiving untrusted `q` parameter without sanitization.
- `backend/services.py`: Intermediate service layer forwarding search keyword.
- `backend/database.py`: Dangerous sink executing raw string-concatenated SQL queries.
- `backend/config.py`: Configuration file that reads credentials from environment variables; no credentials are committed.
- `middleware/auth.py`: Authentication middleware with logic bypass edge cases.
- `utils/helpers.py`: Loose ends (TODO, FIXME, pass, NotImplementedError).
