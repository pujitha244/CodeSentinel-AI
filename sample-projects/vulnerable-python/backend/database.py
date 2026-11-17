# backend/database.py
import sqlite3
from typing import List, Dict, Any

class DatabaseManager:
    def __init__(self, db_path: str = "app.db"):
        self.db_path = db_path

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def execute_raw_search(self, search_term: str) -> List[Dict[str, Any]]:
        """
        DANGEROUS SINK:
        SQL Injection vulnerability!
        Constructs an unsafe query using string formatting with untrusted user input
        rather than parameterized queries.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # SINK: Direct string formatting / concatenation in SQL query
        query = f"SELECT id, username, email, role FROM users WHERE username = '{search_term}' OR email = '{search_term}'"
        
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            return [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]
        finally:
            conn.close()

    def find_user_by_id(self, user_id: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        # Safe parameterized query for contrast
        cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}
        return None

    def delete_record(self, table: str, record_id: int):
        # Potential command/SQL injection if table is untrusted
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {table} WHERE id = ?", (record_id,))
        conn.commit()
        conn.close()
        return {"deleted": True, "id": record_id}

    # Code Slop: Duplicate logic block #2 (identical pattern to UserService.format_user_display_name_v1)
    def format_user_display_name_v2(self, first_name: str, last_name: str, prefix: str = ""):
        clean_first = first_name.strip().title() if first_name else "Anonymous"
        clean_last = last_name.strip().title() if last_name else ""
        if prefix:
            return f"{prefix} {clean_first} {clean_last}".strip()
        return f"{clean_first} {clean_last}".strip()
