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
    if user["is_admin"] == 1:
        response = RedirectResponse("/admin", status_code=303)
    else:
        response = RedirectResponse("/profile", status_code=303)
    response.set_cookie("username", user["username"])
    response.set_cookie("is_admin", str(user["is_admin"]))
    return response


@app.get("/profile")
def profile(username: Optional[str] = Cookie(None)):
    if not username:
        return RedirectResponse("/", status_code=303)
    with open("profile.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/admin")
def admin(username: Optional[str] = Cookie(None), is_admin: Optional[str] = Cookie(None)):
    if not username or is_admin != "1":
        return RedirectResponse("/", status_code=303)
    with open("admin.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())


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


# --- CART APIs ---

@app.get("/cart")
def cart_page(username: Optional[str] = Cookie(None)):
    if not username:
        return RedirectResponse("/", status_code=303)
    with open("cart.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/api/cart/")
def get_cart(request: Request):
    username = request.cookies.get("username")
    if not username:
        return JSONResponse([])
    db = get_db()
    items = db.execute("""
        SELECT c.id, c.quantity, p.name, p.price, p.image 
        FROM cart c 
        JOIN products p ON c.product_id = p.id 
        WHERE c.username = ?
    """, (username,)).fetchall()
    db.close()
    return JSONResponse([dict(i) for i in items])

@app.post("/api/cart/add")
async def add_to_cart(request: Request):
    username = request.cookies.get("username")
    if not username:
        return JSONResponse({"error": "You must be logged in to add to cart"})
    body = await request.json()
    product_id = body.get("product_id")
    
    db = get_db()
    existing = db.execute("SELECT * FROM cart WHERE username=? AND product_id=?", (username, product_id)).fetchone()
    if existing:
        db.execute("UPDATE cart SET quantity = quantity + 1 WHERE id=?", (existing["id"],))
    else:
        db.execute("INSERT INTO cart (username, product_id, quantity) VALUES (?,?,?)", (username, product_id, 1))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.delete("/api/cart/{cart_id}")
def remove_from_cart(cart_id: int, request: Request):
    username = request.cookies.get("username")
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    db.execute("DELETE FROM cart WHERE id=? AND username=?", (cart_id, username))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})


# --- ADMIN APIs ---

def check_admin(request: Request):
    return request.cookies.get("username") and request.cookies.get("is_admin") == "1"

@app.get("/api/admin/products")
def admin_get_products(request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    db.close()
    return JSONResponse([dict(p) for p in products])

@app.post("/api/admin/products")
async def admin_add_product(request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    db.execute(
        "INSERT INTO products (name, description, price, image, hidden) VALUES (?, ?, ?, ?, ?)",
        (body.get("name"), body.get("description"), body.get("price"), body.get("image", "placeholder.jpg"), body.get("hidden", 0))
    )
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.post("/api/admin/products/{product_id}/edit")
async def admin_edit_product(product_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    db.execute(
        "UPDATE products SET name=?, description=?, price=?, image=? WHERE id=?",
        (body.get("name"), body.get("description"), body.get("price"), body.get("image"), product_id)
    )
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.post("/api/admin/products/{product_id}/hide")
async def admin_hide_show_product(product_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    db.execute("UPDATE products SET hidden=? WHERE id=?", (body.get("hidden"), product_id))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.post("/api/admin/products/{product_id}/delete")
def admin_delete_product(product_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    db.execute("DELETE FROM products WHERE id=?", (product_id,))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.get("/api/admin/orders")
def admin_get_orders(request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    orders = db.execute("SELECT * FROM orders").fetchall()
    orders_list = []
    for o in orders:
        order_dict = dict(o)
        items = db.execute("SELECT oi.*, p.name, p.image FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?", (o["id"],)).fetchall()
        order_dict["items"] = [dict(i) for i in items]
        orders_list.append(order_dict)
    db.close()
    return JSONResponse(orders_list)

@app.post("/api/admin/orders/{order_id}/status")
async def admin_update_order_status(order_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    db.execute("UPDATE orders SET status=? WHERE id=?", (body.get("status"), order_id))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.get("/api/admin/users")
def admin_get_users(request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    users = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    db.close()
    return JSONResponse([dict(u) for u in users])

@app.post("/api/admin/users/{user_id}/admin")
async def admin_set_user_admin(user_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    db.execute("UPDATE users SET is_admin=? WHERE id=?", (body.get("is_admin"), user_id))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.post("/api/admin/users/{user_id}/block")
def admin_block_user(user_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})