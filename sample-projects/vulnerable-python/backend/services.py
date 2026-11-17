# backend/services.py
import os
import sys
import math  # Code Slop: Unused import
from backend.database import DatabaseManager

class UserService:
    def __init__(self):
        self.db = DatabaseManager()

    def search_users(self, query_string: str):
        """
        Intermediate propagation function:
        Receives untrusted query_string from routes.py,
        does not sanitize it, and passes it along to the database layer.
        """
        # Intermediate assignment / transformation
        normalized_query = query_string.strip()
        
        # Propagating data to the database operation sink
        records = self.db.execute_raw_search(normalized_query)
        return records

    def get_profile_by_id(self, user_id: int):
        return self.db.find_user_by_id(user_id)

    def delete_user(self, user_id: int):
        return self.db.delete_record("users", user_id)

    # Code Slop: Dead / unreferenced function
    def calculate_legacy_affinity_score(self, user_id: int, factor: float):
        score = 0
        for i in range(10):
            score += i * factor
            for j in range(5):
                score += (i + j) * 0.1
        return score

    # Code Slop: Duplicate logic block #1
    def format_user_display_name_v1(self, first_name: str, last_name: str, prefix: str = ""):
        clean_first = first_name.strip().title() if first_name else "Anonymous"
        clean_last = last_name.strip().title() if last_name else ""
        if prefix:
            return f"{prefix} {clean_first} {clean_last}".strip()
        return f"{clean_first} {clean_last}".strip()
