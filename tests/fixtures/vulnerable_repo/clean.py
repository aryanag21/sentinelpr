"""Clean test fixture: must produce zero findings under all scanners."""


def compute_total(values: list[float], tax_rate: float = 0.05) -> float:
    """Computes total with tax applied safely."""
    subtotal = sum(values)
    return round(subtotal * (1.0 + tax_rate), 2)


def format_user_greeting(username: str) -> str:
    """Safely formats greeting without injection risks."""
    clean_name = username.strip()
    return f"Hello, {clean_name}!"
