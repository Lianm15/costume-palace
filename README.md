# Costume Palace

A Purim costume e-commerce web application intentionally built with security vulnerabilities for educational purposes. Used as a CTF (Capture The Flag) challenge platform for an Advanced Cybersecurity course.

The store is fully functional — customers can browse costumes, add to cart, write reviews, chat with an AI assistant, and place orders. Hidden within the application are 9 security vulnerabilities for students to discover and exploit.

---

## Tech Stack

- **Backend:** Python / FastAPI
- **Database:** SQLite (file: `costumepalace.db`)
- **Frontend:** Plain HTML + CSS + JavaScript
- **AI Chatbot:** [Ollama](https://ollama.com) running locally (model: `llama3.2`)

---

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install fastapi uvicorn[standard] httpx python-multipart
```

### 2. Set up Ollama (required for the AI chatbot)

1. Download and install Ollama from https://ollama.com
2. Pull the required model:

```bash
ollama pull llama3.2
```

3. Start the Ollama service (it runs on `http://localhost:11434` by default):

```bash
ollama serve
```

> The web app works without Ollama — the chatbot will show a friendly offline message if Ollama is not running. All other features (store, cart, checkout, admin) remain functional.

### 3. Run the application

```bash
uvicorn main:app --reload
```

The app will be available at: **127.0.0.1:8000**

---

## Default Accounts

| Username | Password | Role  |
|----------|----------|-------|
| admin    | 1234     | Admin |

Additional accounts can be registered from the homepage.

---

## Challenge System

The application includes 9 hidden security challenges. Open the **"Palace Secrets"** drawer in the top navigation bar to see your progress, view hints, and track which challenges you have solved.

Challenges cover vulnerabilities from:
- OWASP Top 10 for Web Applications
- OWASP LLM Top 10

---

## Project Structure

```
costume-palace/
├── main.py          # FastAPI backend — all routes and logic
├── database.py      # SQLite schema and seed data
├── homepage.html    # Main storefront
├── profile.html     # User profile management
├── admin.html       # Admin dashboard
├── cart.html        # Shopping cart
├── wishlist.html    # Wishlist
├── checkout.html    # Order checkout
├── style.css        # Global styles
├── images/          # Product images
└── costumepalace.db # SQLite database (auto-created on first run)
```

---

## Troubleshooting

**App won't start — "module not found"**
Run `pip install -r requirements.txt` to install all dependencies.

**Database errors on startup**
Delete `costumepalace.db` and restart the app — it will be recreated with fresh seed data.

**Chatbot always shows "offline" message**
Make sure Ollama is installed and running (`ollama serve`), and that the `llama3.2` model has been pulled (`ollama pull llama3.2`).

**Port 8000 already in use**
Run on a different port: `uvicorn main:app --reload --port 8080`

**Changes to HTML/CSS not reflected**
The app serves static files directly. Hard-refresh the browser (`Ctrl+Shift+R`) to bypass the cache.
