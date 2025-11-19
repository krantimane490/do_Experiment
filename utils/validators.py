def validate_title(title: str):
    if not title or len(title.strip()) == 0:
        raise ValueError("Title cannot be empty.")
    if len(title) > 100:
        raise ValueError("Title too long.")
