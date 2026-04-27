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

@app.get("/wishlist")
def serve_wishlist(username: Optional[str] = Cookie(None)):
    if not username:
        return RedirectResponse("/", status_code=303)
    with open("wishlist.html", encoding="utf-8") as f:
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
        "SELECT * FROM reviews WHERE product_id = ? AND hidden = 0", (product_id,)
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


# --- CHECKOUT APIs ---

@app.get("/checkout")
def serve_checkout(username: Optional[str] = Cookie(None)):
    if not username:
        return RedirectResponse("/", status_code=303)
        
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM cart WHERE username=?", (username,)).fetchone()[0]
    db.close()
    
    if count == 0:
        return RedirectResponse("/cart", status_code=303)
        
    with open("checkout.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/api/checkout")
async def handle_checkout(request: Request):
    username = request.cookies.get("username")
    if not username:
        return JSONResponse({"error": "unauthorized"}, status_code=403)
    
    try:
        body = await request.json()
    except:
        body = {}
        
    phone = body.get("phone", "")
    email = body.get("email", "")
    postal = body.get("postal", "")
    
    db = get_db()
    if username:
        if body.get("save_address"):
            db.execute("INSERT INTO user_addresses (username, address_name, address, postal_code) VALUES (?,?,?,?)", 
                       (username, body.get("address_name") or "Saved Address", body.get("address", ""), postal))
        if body.get("save_payment"):
            db.execute("INSERT INTO user_payments (username, card_name, card_number, expiry, cvv) VALUES (?,?,?,?,?)",
                       (username, body.get("card_name") or "Saved Card", body.get("card_number", ""), body.get("expiry", ""), body.get("cvv", "")))
    
    if not phone or not phone.startswith("0") or len(phone) != 10 or not phone.isdigit():
        return JSONResponse({"error": "Invalid phone number"}, status_code=400)
    if not email or not email.endswith("@gmail.com"):
        return JSONResponse({"error": "Invalid email address"}, status_code=400)
    if not postal or len(postal) != 7 or not postal.isdigit():
        db.close()
        return JSONResponse({"error": "Invalid postal code"}, status_code=400)
    items = db.execute("""
        SELECT c.quantity, p.id as product_id, p.price 
        FROM cart c 
        JOIN products p ON c.product_id = p.id 
        WHERE c.username = ?
    """, (username,)).fetchall()
    
    if not items:
        db.close()
        return JSONResponse({"error": "Cart is empty"}, status_code=400)
    
    total = sum(i["quantity"] * i["price"] for i in items)
    
    cursor = db.execute("INSERT INTO orders (username, total, status) VALUES (?,?,?)", (username, total, "Pending"))
    order_id = cursor.lastrowid
    
    for i in items:
        db.execute("INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?,?,?,?)", 
                   (order_id, i["product_id"], i["quantity"], i["price"]))
                   
    db.execute("DELETE FROM cart WHERE username=?", (username,))
    db.commit()
    db.close()
    
    return JSONResponse({"ok": True, "order_id": order_id})


# --- WISHLIST APIs ---
@app.get("/api/wishlist")
def get_wishlist(request: Request):
    username = request.cookies.get("username")
    if not username: return JSONResponse([])
    db = get_db()
    items = db.execute("""
        SELECT p.*
        FROM wishlist w
        JOIN products p ON w.product_id = p.id
        WHERE w.username = ? AND p.hidden = 0
    """, (username,)).fetchall()
    db.close()
    return JSONResponse([dict(i) for i in items])

@app.post("/api/wishlist/toggle")
async def toggle_wishlist(request: Request):
    username = request.cookies.get("username")
    if not username: return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    product_id = body.get("product_id")
    db = get_db()
    existing = db.execute("SELECT * FROM wishlist WHERE username=? AND product_id=?", (username, product_id)).fetchone()
    if existing:
        db.execute("DELETE FROM wishlist WHERE id=?", (existing["id"],))
        added = False
    else:
        db.execute("INSERT INTO wishlist (username, product_id) VALUES (?,?)", (username, product_id))
        added = True
    db.commit()
    db.close()
    return JSONResponse({"ok": True, "added": added})

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
    row = db.execute("SELECT quantity FROM cart WHERE id=? AND username=?", (cart_id, username)).fetchone()
    if not row:
        db.close()
        return JSONResponse({"error": "item not found"}, status_code=404)
        
    if row["quantity"] > 1:
        db.execute("UPDATE cart SET quantity = ? WHERE id=?", (row["quantity"] - 1, cart_id))
    else:
        db.execute("DELETE FROM cart WHERE id=?", (cart_id,))
        
    db.commit()
    db.close()
    return JSONResponse({"ok": True})


# --- PROFILE APIs ---
@app.get("/api/profile")
def get_user_profile(request: Request):
    username = request.cookies.get("username")
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
    
    db = get_db()
    user = db.execute("SELECT id, username, full_name, email, phone, address, postal_code FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    
    if not user:
        return JSONResponse({"error": "User not found"}, status_code=404)
        
    return JSONResponse(dict(user))

@app.post("/api/profile")
async def update_user_profile(request: Request):
    username = request.cookies.get("username")
    if not username:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
        
    try:
        body = await request.json()
    except Exception:
        body = {}
        
    db = get_db()
    db.execute("""
        UPDATE users 
        SET full_name=?, email=?, phone=?, address=?, postal_code=? 
        WHERE username=?
    """, (
        body.get("full_name"), 
        body.get("email"), 
        body.get("phone"), 
        body.get("address"), 
        body.get("postal_code"), 
        username
    ))
    db.commit()
    db.close()
    
    return JSONResponse({"ok": True})


# --- PROFILE MULTI-ENTRY APIs ---
@app.get("/api/profile/addresses")
def get_user_addresses(request: Request):
    username = request.cookies.get("username")
    if not username: return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    data = db.execute("SELECT * FROM user_addresses WHERE username=?", (username,)).fetchall()
    db.close()
    return JSONResponse([dict(r) for r in data])

@app.post("/api/profile/addresses")
async def add_user_address(request: Request):
    username = request.cookies.get("username")
    if not username: return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    db.execute("INSERT INTO user_addresses (username, address_name, address, postal_code) VALUES (?,?,?,?)", 
               (username, body.get('address_name'), body.get('address'), body.get('postal_code')))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})
    
@app.delete("/api/profile/addresses/{address_id}")
def delete_user_address(request: Request, address_id: int):
    username = request.cookies.get("username")
    if not username: return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    db.execute("DELETE FROM user_addresses WHERE id=? AND username=?", (address_id, username))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.get("/api/profile/payments")
def get_user_payments(request: Request):
    username = request.cookies.get("username")
    if not username: return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    data = db.execute("SELECT * FROM user_payments WHERE username=?", (username,)).fetchall()
    db.close()
    return JSONResponse([dict(r) for r in data])

@app.post("/api/profile/payments")
async def add_user_payment(request: Request):
    username = request.cookies.get("username")
    if not username: return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    db.execute("INSERT INTO user_payments (username, card_name, card_number, expiry, cvv) VALUES (?,?,?,?,?)", 
               (username, body.get('card_name'), body.get('card_number'), body.get('expiry'), body.get('cvv')))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.delete("/api/profile/payments/{payment_id}")
def delete_user_payment(request: Request, payment_id: int):
    username = request.cookies.get("username")
    if not username: return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    db.execute("DELETE FROM user_payments WHERE id=? AND username=?", (payment_id, username))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})
@app.get("/api/orders")
def get_orders(request: Request):
    username = request.cookies.get("username")
    if not username:
        return JSONResponse([])

    db = get_db()
    orders = db.execute("SELECT * FROM orders WHERE username=?", (username,)).fetchall()
    db.close()

    return JSONResponse([dict(o) for o in orders])

@app.get("/api/orders/{order_id}")
def get_order_items(order_id: int, request: Request):
    username = request.cookies.get("username")
    if not username:
        return JSONResponse([])

    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=? AND username=?", (order_id, username)).fetchone()
    if not order:
        db.close()
        return JSONResponse([])

    items = db.execute("""
        SELECT p.name, p.image, oi.price_at_purchase as price, oi.quantity
        FROM order_items oi
        LEFT JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id=?
    """, (order_id,)).fetchall()

    results = []
    for i in items:
        d = dict(i)
        if d["name"] is None:
            d["name"] = "Deleted Product"
            d["image"] = "placeholder.jpg"
        results.append(d)

    db.close()
    return JSONResponse(results)


# --- ADMIN APIs ---

def check_admin(request: Request):
    return request.cookies.get("username") and request.cookies.get("is_admin") == "1"

def log_audit(db, request: Request, action: str, target_type: str, target_id: int, details: str = ""):
    admin_username = request.cookies.get("username", "unknown")
    try:
        db.execute(
            "INSERT INTO audit_logs (admin_username, action, target_type, target_id, details) VALUES (?,?,?,?,?)",
            (admin_username, action, target_type, target_id, details)
        )
    except:
        pass

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
    cursor = db.execute(
        "INSERT INTO products (name, description, price, image, hidden) VALUES (?, ?, ?, ?, ?)",
        (body.get("name"), body.get("description"), body.get("price"), body.get("image", "placeholder.jpg"), body.get("hidden", 0))
    )
    product_id = cursor.lastrowid
    log_audit(db, request, "Create", "Product", product_id, f"Created product '{body.get('name')}'")
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
    log_audit(db, request, "Edit", "Product", product_id, f"Edited product '{body.get('name')}'")
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.post("/api/admin/products/{product_id}/hide")
async def admin_hide_show_product(product_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    db.execute("UPDATE products SET hidden=? WHERE id=?", (body.get("hidden"), product_id))
    action = "Hide" if body.get("hidden") else "Show"
    log_audit(db, request, action, "Product", product_id)
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.post("/api/admin/products/{product_id}/delete")
def admin_delete_product(product_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    db.execute("DELETE FROM products WHERE id=?", (product_id,))
    log_audit(db, request, "Delete", "Product", product_id)
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
        items = db.execute("""
            SELECT oi.*, IFNULL(p.name, 'Deleted Product') as name, IFNULL(p.image, 'placeholder.jpg') as image 
            FROM order_items oi 
            LEFT JOIN products p ON oi.product_id = p.id 
            WHERE oi.order_id = ?
        """, (o["id"],)).fetchall()
        order_dict["items"] = [dict(i) for i in items]
        orders_list.append(order_dict)
    db.close()
    return JSONResponse(orders_list)

@app.post("/api/admin/orders/{order_id}/status")
async def admin_update_order_status(order_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    db = get_db()
    status = body.get("status")
    db.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
    log_audit(db, request, "Status Change", "Order", order_id, f"Changed status to '{status}'")
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

# User permission settings removed to prevent destructive actions by admins

@app.get("/api/admin/reviews")
def admin_get_reviews(request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    reviews = db.execute("""
        SELECT r.*, p.name as product_name
        FROM reviews r
        JOIN products p ON r.product_id = p.id
    """).fetchall()
    db.close()
    return JSONResponse([dict(r) for r in reviews])

@app.post("/api/admin/reviews/{review_id}/hide")
async def admin_hide_review(review_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    body = await request.json()
    hidden = body.get("hidden", 1)
    db = get_db()
    db.execute("UPDATE reviews SET hidden=? WHERE id=?", (hidden, review_id))
    action = "Hide" if hidden else "Unhide"
    log_audit(db, request, action, "Review", review_id)
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.post("/api/admin/reviews/{review_id}/delete")
def admin_delete_review(review_id: int, request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    db.execute("DELETE FROM reviews WHERE id=?", (review_id,))
    log_audit(db, request, "Delete", "Review", review_id)
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.get("/api/admin/analytics")
def admin_get_analytics(request: Request):
    if not check_admin(request): return JSONResponse({"error": "Unauthorized"}, status_code=403)
    db = get_db()
    
    total_rev = db.execute("""
        SELECT SUM(oi.quantity * COALESCE(oi.price_at_purchase, p.price)) 
        FROM order_items oi 
        JOIN orders o ON oi.order_id = o.id 
        JOIN products p ON oi.product_id = p.id
        WHERE o.status != 'Cancelled'
    """).fetchone()[0] or 0
    
    monthly_rev = db.execute("""
        SELECT SUM(oi.quantity * COALESCE(oi.price_at_purchase, p.price)) 
        FROM order_items oi 
        JOIN orders o ON oi.order_id = o.id 
        JOIN products p ON oi.product_id = p.id
        WHERE o.status != 'Cancelled' 
        AND strftime('%Y-%m', o.created_at) = strftime('%Y-%m', 'now')
    """).fetchone()[0] or 0
    
    best_product = db.execute("""
        SELECT p.name, SUM(oi.quantity) as sold
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        JOIN orders o ON oi.order_id = o.id
        WHERE o.status != 'Cancelled'
        GROUP BY oi.product_id
        ORDER BY sold DESC
        LIMIT 1
    """).fetchone()
    best_product_name = best_product["name"] if best_product else "N/A"
    
    best_customer = db.execute("""
        SELECT username, COUNT(id) as order_count
        FROM orders
        WHERE status != 'Cancelled'
        GROUP BY username
        ORDER BY order_count DESC
        LIMIT 1
    """).fetchone()
    best_customer_name = best_customer["username"] if best_customer and best_customer["username"] else "Guest/None"
    
    rev_count = db.execute("""
        SELECT COUNT(DISTINCT o.id), SUM(oi.quantity * COALESCE(oi.price_at_purchase, p.price))
        FROM order_items oi 
        JOIN orders o ON oi.order_id = o.id 
        JOIN products p ON oi.product_id = p.id
        WHERE o.status != 'Cancelled'
    """).fetchone()
    avg_order = (rev_count[1] / rev_count[0]) if rev_count and rev_count[0] else 0
    
    monthly_data = db.execute("""
        SELECT IFNULL(strftime('%Y-%m', o.created_at), 'Unknown') as month, SUM(oi.quantity * COALESCE(oi.price_at_purchase, p.price)) as rev
        FROM order_items oi 
        JOIN orders o ON oi.order_id = o.id 
        JOIN products p ON oi.product_id = p.id
        WHERE o.status != 'Cancelled'
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()
    
    product_dist = db.execute("""
        SELECT p.name, SUM(oi.quantity) as sold
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        JOIN orders o ON oi.order_id = o.id
        WHERE o.status != 'Cancelled'
        GROUP BY oi.product_id
    """).fetchall()
    
    db.close()
    
    return JSONResponse({
        "total_revenue": round(total_rev, 2),
        "monthly_revenue": round(monthly_rev, 2),
        "best_product": best_product_name,
        "best_customer": best_customer_name,
        "avg_order_value": round(avg_order, 2),
        "monthly_chart": [{"month": m["month"], "rev": m["rev"] or 0} for m in monthly_data],
        "product_chart": [{"name": p["name"], "sold": p["sold"] or 0} for p in product_dist]
    })