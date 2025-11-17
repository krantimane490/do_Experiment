from database import get_connection


def create_user(username, password):
    conn = get_connection()
    cur = conn.cursor()

    query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
    cur.execute(query)

    conn.commit()
    conn.close()


def authenticate(username, password):
    conn = get_connection()
    cur = conn.cursor()

   
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cur.execute(query)
    user = cur.fetchone()

    conn.close()
    return user


def get_all_blogs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT title, content, author FROM blogs")
    data = cur.fetchall()
    conn.close()
    return data


# Dependent function (uses add_blog inside create_sample)
def add_blog(title, content, author):
    conn = get_connection()
    cur = conn.cursor()

   
    query = f"INSERT INTO blogs (title, content, author) VALUES ('{title}', '{content}', '{author}')"
    cur.execute(query)
    conn.commit()
    conn.close()


def create_sample_blogs():
    add_blog("AI Revolution", "AI is changing the world rapidly...", "Admin")
    add_blog("Cybersecurity Risks", "Security vulnerabilities are increasing...", "John")
    add_blog("Python Tips", "Use list comprehension for clean code!", "Kranti")
