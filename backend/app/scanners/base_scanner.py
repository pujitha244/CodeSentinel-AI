from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScanner(ABC):
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category

    @abstractmethod
    def is_available(self) -> bool:
        """Check if any external binary or runner is available."""
        pass

    @abstractmethod
    def scan(self, project_root: str, target_files: List[str]) -> List[Dict[str, Any]]:
        """
        Execute scan on project and return standardized findings:
        [
          {
             "title": str,
             "category": str,
             "severity": "critical"|"high"|"medium"|"low"|"info",
             "confidence": float,
             "file_path": str,
             "start_line": int,
             "end_line": int,
             "snippet": str,
             "description": str,
             "impact": str,
             "recommendation": str,
             "verification": str,
             "detection_method": str
          }
        ]
        """
        pass
