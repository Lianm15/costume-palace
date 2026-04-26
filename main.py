from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from database import get_db, init_db

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


@app.post("/api/cart/add")
async def add_to_cart(request: Request):
    data = await request.json()
    username = request.cookies.get("username")

    if not username:
        return JSONResponse({"error: not logged in"}, status_code=401)
    
    product_id = data.get("product_id")
    db = get_db()

    existing = db.execute("SELECT * FROM cart WHERE username=? AND product_id=?", (username, product_id)).fetchone()

    if existing:
        db.execute("UPDATE cart SET quantity = quantity + 1 WHERE id=?", (existing["id"],))
    
    else:
        db.execute("INSERT INTO cart (username, product_id, quantity) VALUES (?, ?, 1)", (username, product_id))

    db.commit()
    db.close()

    return {"ok": True}

@app.get("/api/cart/")
def get_cart(request: Request):
    username = request.cookies.get("username")

    if not username:
        return JSONResponse([], status_code=200)
    
    db = get_db()

    items = db.execute("""
        SELECT cart.id, products.name, products.price, products.image, cart.quantity
        FROM cart
        JOIN products ON cart.product_id = products.id
        WHERE cart.username=?
    """, (username,)).fetchall()
    
    db.close()
    return JSONResponse([dict(item) for item in items])


@app.delete("/api/cart/{item_id}")
def remove_from_cart(item_id: int):
    db = get_db()

    row = db.execute(
        "SELECT quantity FROM cart WHERE id=?", 
        (item_id,)
    ).fetchone()

    if not row:
        db.close()
        return {"error": "item not found"}

    quantity = row["quantity"] 

    if quantity > 1:
        new_quantity = quantity - 1
        db.execute(
            "UPDATE cart SET quantity = ? WHERE id=?",
            (new_quantity, item_id)
        )
    else:
        db.execute(
            "DELETE FROM cart WHERE id=?",
            (item_id,)
        )
        new_quantity = 0

    db.commit()
    db.close()

    return {"quantity": new_quantity}  

@app.get("/cart")
def cart_page():
    with open("cart.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())
    

@app.get("/checkout")
def checkout_page():
    with open("checkout.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())
    
@app.post("/api/checkout")
def checkout(request: Request):
    username = request.cookies.get("username")
    db = get_db()

    items = db.execute("""
        SELECT product_id, quantity, products.price
        FROM cart
        JOIN products ON cart.product_id = products.id
        WHERE cart.username=?
    """, (username,)).fetchall()

    total = sum(item["price"] * item["quantity"] for item in items)

    cursor = db.execute(
        "INSERT INTO orders (username, total) VALUES (?, ?)",
        (username, total)
    )
    order_id = cursor.lastrowid

    for item in items:
        db.execute("""
            INSERT INTO order_items (order_id, product_id, quantity)
            VALUES (?, ?, ?)
        """, (order_id, item["product_id"], item["quantity"]))

    db.execute("DELETE FROM cart WHERE username=?", (username,))
    db.commit()
    db.close()

    return {"message": "Order Completed"}

@app.get("/profile")
def profile_page():
    with open("profile.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())
    
@app.get("/api/orders")
def get_orders(request: Request):
    username = request.cookies.get("username")

    db = get_db()
    orders= db.execute("SELECT * FROM orders WHERE username=?", (username,)).fetchall()
    db.close()

    return JSONResponse([dict(o) for o in orders])

@app.get("/api/orders/{order_id}")
def get_order_items(order_id: int):
    db = get_db()

    items = db.execute("""
        SELECT products.name, products.image, products.price, order_items.quantity
        FROM order_items
        JOIN products ON order_items.product_id = products.id
        WHERE order_items.order_id=?
    """, (order_id,)).fetchall()

    db.close()
    return JSONResponse([dict(i) for i in items])

