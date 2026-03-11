import sqlite3


# -------------------------------------------------
# Open connection to the SQLite database
# row_factory allows accessing columns by name
# -------------------------------------------------
def get_db():
    conn = sqlite3.connect("costumepalace.db")
    conn.row_factory = sqlite3.Row
    return conn


# -------------------------------------------------
# Create database tables and insert seed data
# -------------------------------------------------
def init_db():
    conn = get_db()

    # -------------------------------------------------
    # Users table
    # Stores login information for users
    # is_admin = 1 means administrator
    # -------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)

    # -------------------------------------------------
    # Products table
    # Stores all costumes in the shop
    # hidden = 1 means the product is not shown in the UI
    # -------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT,
            description TEXT,
            price       REAL,
            image       TEXT,
            hidden      INTEGER DEFAULT 0
        )
    """)

    # -------------------------------------------------
    # Reviews table
    # Stores user reviews for products
    # -------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            username   TEXT,
            content    TEXT,
            rating     INTEGER
        )
    """)

    conn.commit()

    # -------------------------------------------------
    # Seed products (only if the table is empty)
    # -------------------------------------------------
    count = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]

    if count == 0:
        products = [
            ("Witch", "Classic witch outfit.", 89.99, "witch.jpg", 0),
            ("Vampire", "Elegant cape, fangs, and medallion. Rise from the coffin in style.", 99.99,"vampire.jpg",0),
            ("Princess", "Feel like real royalty.", 79.99, "princess.jpg", 0),
            ("Panda", "The cutest Panda bear in Israel.",169.99, "panda.jpg", 0),
            ("Zombie", "A creepy zombie look",  94.99, "zombie.jpg", 0),
            ("Clown", "Classic clown outfit ready to bring laughs to the party.", 74.99, "clown.jpg", 0),
            ("Spiderman", "Full suit inspired by the famous hero.", 109.99, "spiderman.jpg", 0),
            ("Pizza", "Be the best Pizza slice at the party.", 109.99, "pizza.jpg" ,0),

            # hidden product (not shown on homepage)
            # Can still be accessed directly via /api/product/9
            # This demonstrates an IDOR vulnerability
            ("Admin Special", "This product is not for sale.", 1000000, "king.jpg", 1),
        ]

        conn.executemany(
            "INSERT INTO products (name, description, price, image, hidden) VALUES (?,?,?,?,?)",
            products
        )

    # -------------------------------------------------
    # Seed admin user (only if admin does not exist)
    # VULNERABILITY:
    # - password stored in plain text
    # - weak password
    # -------------------------------------------------
    admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()

    if not admin:
        conn.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            ("admin", "1234", 1)
        )

    # -------------------------------------------------
    # Seed product reviews (only if table is empty)
    # -------------------------------------------------
    review_count = conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]

    if review_count == 0:
        reviews = [
            (1, "lian", "Amazing quality! Wore it to three Purim parties.", 5),
            (1, "dina",    "Hat was a bit small.", 4),
            (2, "shahar",  "So dramatic and elegant. Everyone was scared of me!", 5),
            (3, "bob",    "My daughter loved it, fit perfectly.", 5),
            (3, "alice",   "took long to arrive.", 3),
            (4, "avi",     "Cutest costume at the party, no competition.", 5),
            (5, "noa",     "Super realistic.", 5),
            (6, "rona",   "Kids were terrified. 10/10.", 5),
            (7, "yossi",   "My son refused to take it off for a week.", 5),
            (8, "limor",   "Became the most popular person at the party instantly.", 5),
        ]

        conn.executemany(
            "INSERT INTO reviews (product_id, username, content, rating) VALUES (?,?,?,?)",
            reviews
        )

    conn.commit()
    conn.close()