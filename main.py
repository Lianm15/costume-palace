from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from database import get_db, init_db
from fastapi import Cookie
from typing import Optional

app = FastAPI()
init_db()

# Serve costume images from the /images folder
app.mount("/images", StaticFiles(directory="images"), name="images")


# Serve style.css from the project root
@app.get("/style.css")
def serve_css():
    return FileResponse("style.css")


# Pages
@app.get("/")
def homepage():
    with open("homepage.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())


# Auth routes

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    db = get_db()

    # VULN SQL Injection: input inserted directly into query string
    # entering:  ' OR '1'='1  as username to bypass authentication
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = db.execute(query).fetchone()
    db.close()

    if not user:
        return HTMLResponse("Wrong credentials. <a href='/'>Try again</a>")

    # Save session in cookies so the page knows who is logged in
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("username", user["username"])
    response.set_cookie("is_admin", str(user["is_admin"]))
    return response


@app.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    db = get_db()
    try:
        # VULN: password stored as plain text, no hashing
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (username, password)
        )
        db.commit()

        # Auto login after register
        response = RedirectResponse("/", status_code=303)
        response.set_cookie("username", username)
        response.set_cookie("is_admin", "0")
        return response
    except:
        return HTMLResponse("Username already taken. <a href='/'>Try again</a>")
    finally:
        db.close()


@app.get("/logout")
def logout():
    # Clear session cookies and return to homepage
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("username")
    response.delete_cookie("is_admin")
    return response


# Products API

@app.get("/api/products")
def get_all_products():
    # Returns only visible products (hidden=0) for the homepage grid
    db = get_db()
    products = db.execute("SELECT * FROM products WHERE hidden = 0").fetchall()
    db.close()
    return JSONResponse([{
        "id":          p["id"],
        "name":        p["name"],
        "description": p["description"],
        "price":       p["price"],
        "image":       p["image"]
    } for p in products])


@app.get("/api/product/{product_id}")
def get_product(product_id: int):
    db = get_db()
    # VULN IDOR: no check for hidden flag — /api/product/9 works just like any other
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    db.close()

    if not product:
        return JSONResponse({"error": "not found"}, status_code=404)

    return JSONResponse({
        "id":          product["id"],
        "name":        product["name"],
        "description": product["description"],
        "price":       product["price"],
        "image":       product["image"],
        "hidden":      product["hidden"]
    })


# Reviews API
@app.get("/api/product/{product_id}/reviews")
def get_reviews(product_id: int):
    db = get_db()
    reviews = db.execute(
        "SELECT * FROM reviews WHERE product_id = ?", (product_id,)
    ).fetchall()
    db.close()

    # VULN XSS: content returned raw, no sanitization
    # When rendered with innerHTML on the frontend, scripts will execute
    return JSONResponse([{
        "username": r["username"],
        "content":  r["content"],
        "rating":   r["rating"]
    } for r in reviews])


@app.post("/api/product/{product_id}/reviews")
async def post_review(product_id: int, request: Request):
    body = await request.json()

    db = get_db()
    db.execute(
        "INSERT INTO reviews (product_id, username, content, rating) VALUES (?,?,?,?)",
        (
            product_id,
            body.get("username"),
            body.get("content"),  # VULN XSS: saved as is, never sanitized
            body.get("rating", 5)
        )
    )
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

    
# Mark challenge as solved
@app.post("/api/challenge/solve")
async def solve_challenge(request: Request, username: Optional[str] = Cookie(None)):
    if not username:
        return JSONResponse({"error": "not logged in"}, status_code=401)
    body = await request.json()
    challenge = body.get("challenge")
    db = get_db()
    try:
        db.execute(
            "INSERT OR IGNORE INTO solved_challenges (username, challenge) VALUES (?, ?)",
            (username, challenge)
        )
        db.commit()
        return JSONResponse({"ok": True})
    finally:
        db.close()

# Get current user's solved challenges
@app.get("/api/challenges")
def get_challenges(username: Optional[str] = Cookie(None)):
    all_challenges = [
        "SQL Injection",
        "XSS",
        "IDOR",
        "Broken Access Control",
        "Plaintext Passwords",
        "Prompt Injection",
        "Insecure Cookie",
        "Security Misconfiguration",
    ]
    if not username:
        return JSONResponse([{"name": c, "solved": False} for c in all_challenges])

    db = get_db()
    solved = db.execute(
        "SELECT challenge FROM solved_challenges WHERE username = ?", (username,)
    ).fetchall()
    db.close()
    solved_names = {r["challenge"] for r in solved}
    return JSONResponse([
        {"name": c, "solved": c in solved_names} for c in all_challenges
    ])

    
@app.get("/api/hints")
def get_hints():
    hints = [
        {
            "name": "SQL Injection",
            "difficulty": "2",
            "hints": [
                "Try logging in with unusual characters in the username field...",
                "What if the username field could change the SQL query logic?"
            ]
        },
        {
            "name": "XSS",
            "difficulty": "2",
            "hints": [
                "User input is displayed somewhere on the page...",
                "What if a review contained HTML instead of plain text?"
            ]
        },
        {
            "name": "IDOR",
            "difficulty": "1",
            "hints": [
                "Product IDs are sequential...",
                "What if you tried an ID that isn't shown on the homepage?"
            ]
        },
        {
            "name": "Broken Access Control",
            "difficulty": "1",
            "hints": [
                "There's an admin panel somewhere on the site...",
                "How does the site know you're an admin?"
            ]
        },
        {
            "name": "Plaintext Passwords",
            "difficulty": "1",
            "hints": [
                "If you could read the database, what would you find?",
                "Are passwords stored securely?"
            ]
        },
        {
            "name": "Prompt Injection",
            "difficulty": "3",
            "hints": [
                "The AI chatbot follows instructions very literally...",
                "What if you gave it new instructions inside your message?"
            ]
        },
        {
            "name": "Insecure Cookie",
            "difficulty": "1",
            "hints": [
                "How does the server know if you're an admin?",
                "Open browser DevTools → Application → Cookies"
            ]
        },
        {
            "name": "Security Misconfiguration",
            "difficulty": "1",
            "hints": [
                "FastAPI exposes something by default...",
                "Check common API documentation paths"
            ]
        },
    ]
    return JSONResponse(hints)
