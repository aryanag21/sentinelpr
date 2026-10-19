# Test fixture containing deliberate SQL injection


def get_user_profile(db_connection, username: str):
    # Deliberate SQL injection via f-string formatting
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    return db_connection.execute(query)
