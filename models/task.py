from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class Task:
    id: int
    title: str
    description: str
    due_date: Optional[datetime]
    is_completed: bool = False
