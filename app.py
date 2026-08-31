from flask import Flask, request, jsonify, session, send_from_directory
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import base64
import urllib.request
import urllib.error
import hmac
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)

DB = os.path.expanduser("~/users.db")

# ₹49 = 4900 paise
PRICE = int(os.environ.get("PREMIUM_PRICE_PAISE", "4900"))

RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# ==================================================
# DATABASE
# ==================================================

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    # Existing users table থাকলে paid column add হবে
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            paid INTEGER DEFAULT 0
        )
    """)

    # Old users.db হলে paid column না থাকলে add করার চেষ্টা
    columns = [
        row["name"]
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    ]

    if "paid" not in columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN paid INTEGER DEFAULT 0"
        )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            razorpay_order_id TEXT UNIQUE NOT NULL,
            amount INTEGER NOT NULL,
            currency TEXT NOT NULL DEFAULT 'INR',
            status TEXT NOT NULL DEFAULT 'created',
            razorpay_payment_id TEXT UNIQUE,
            razorpay_signature TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# ==================================================
# CURRENT USER
# ==================================================

def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = db()

    user = conn.execute(
        """
        SELECT id, name, email, paid
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:
        session.clear()
        return None

    return user


# ==================================================
# RAZORPAY API
# ==================================================

def razorpay_request(method, endpoint, payload=None):

    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise RuntimeError(
            "RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET missing"
        )

    auth = base64.b64encode(
        f"{RAZORPAY_KEY_ID}:{RAZORPAY_KEY_SECRET}".encode()
    ).decode()

    url = "https://api.razorpay.com/v1" + endpoint

    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        method=method
    )

    req.add_header(
        "Authorization",
        "Basic " + auth
    )

    req.add_header(
        "Content-Type",
        "application/json"
    )

    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(
            response.read().decode("utf-8")
        )


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():
    return send_from_directory(
        os.path.dirname(os.path.abspath(__file__)),
        "index.html"
    )


# ==================================================
# REGISTER
# ==================================================

@app.route("/register", methods=["POST"])
def register():

    data = request.get_json(silent=True) or {}

    name = str(
        data.get("name", "")
    ).strip()

    email = str(
        data.get("email", "")
    ).strip().lower()

    password = str(
        data.get("password", "")
    )

    if not name or not email or not password:
        return jsonify(
            success=False,
            message="সবগুলো ঘর পূরণ করুন।"
        ), 400

    if len(password) < 6:
        return jsonify(
            success=False,
            message="Password কমপক্ষে 6 characters হতে হবে।"
        ), 400

    conn = db()

    try:

        conn.execute(
            """
            INSERT INTO users
            (name, email, password, paid)
            VALUES (?, ?, ?, 0)
            """,
            (
                name,
                email,
                generate_password_hash(password)
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify(
            success=False,
            message="এই Email দিয়ে আগে থেকেই account আছে।"
        ), 409

    conn.close()

    return jsonify(
        success=True,
        message="Registration successful!"
    )


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    email = str(
        data.get("email", "")
    ).strip().lower()

    password = str(
        data.get("password", "")
    )

    conn = db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conn.close()

    if (
        not user
        or not check_password_hash(
            user["password"],
            password
        )
    ):

        return jsonify(
            success=False,
            message="Email অথবা Password ভুল।"
        ), 401

    session.clear()
    session["user_id"] = user["id"]

    return jsonify(
        success=True,
        user={
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "paid": bool(user["paid"])
        }
    )


# ==================================================
# ME
# ==================================================

@app.route("/me")
def me():

    user = get_current_user()

    if not user:
        return jsonify(
            logged_in=False
        )

    return jsonify(
        logged_in=True,
        user={
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "paid": bool(user["paid"])
        }
    )


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return jsonify(
        success=True
    )


# ==================================================
# CREATE RAZORPAY ORDER
# ==================================================

@app.route(
    "/create-razorpay-order",
    methods=["POST"]
)
def create_razorpay_order():

    user = get_current_user()

    if not user:
        return jsonify(
            success=False,
            message="Login required"
        ), 401

    if user["paid"]:

        return jsonify(
            success=False,
            message="Premium already active"
        ), 400

    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:

        return jsonify(
            success=False,
            message="Razorpay keys configure nahi kiye gaye."
        ), 503

    try:

        order = razorpay_request(
            "POST",
            "/orders",
            {
                "amount": PRICE,
                "currency": "INR",
                "receipt": (
                    f"premium_{user['id']}_"
                    f"{os.urandom(5).hex()}"
                ),
                "notes": {
                    "user_id": str(user["id"]),
                    "plan": "premium_lifetime"
                }
            }
        )

        conn = db()

        conn.execute(
            """
            INSERT INTO orders
            (
                user_id,
                razorpay_order_id,
                amount,
                currency,
                status
            )
            VALUES (?, ?, ?, ?, 'created')
            """,
            (
                user["id"],
                order["id"],
                order["amount"],
                order["currency"]
            )
        )

        conn.commit()
        conn.close()

        return jsonify(
            success=True,
            razorpay_key=RAZORPAY_KEY_ID,
            order_id=order["id"],
            amount=order["amount"],
            currency=order["currency"]
        )

    except Exception as error:

        app.logger.error(
            "Razorpay order error: %s",
            error
        )

        return jsonify(
            success=False,
            message="Razorpay order create nahi hua."
        ), 502


# ==================================================
# VERIFY PAYMENT
# ==================================================

@app.route(
    "/verify-payment",
    methods=["POST"]
)
def verify_payment():

    user = get_current_user()

    if not user:
        return jsonify(
            success=False,
            message="Login required"
        ), 401

    data = request.get_json(
        silent=True
    ) or {}

    payment_id = str(
        data.get(
            "razorpay_payment_id",
            ""
        )
    )

    order_id = str(
        data.get(
            "razorpay_order_id",
            ""
        )
    )

    signature = str(
        data.get(
            "razorpay_signature",
            ""
        )
    )

    if not payment_id or not order_id or not signature:

        return jsonify(
            success=False,
            message="Payment response incomplete hai."
        ), 400

    conn = db()

    order = conn.execute(
        """
        SELECT *
        FROM orders
        WHERE razorpay_order_id = ?
        AND user_id = ?
        """,
        (
            order_id,
            user["id"]
        )
    ).fetchone()

    if not order:

        conn.close()

        return jsonify(
            success=False,
            message="Order verify nahi hua."
        ), 400

    if order["razorpay_payment_id"]:

        conn.close()

        return jsonify(
            success=False,
            message="Payment already processed."
        ), 409

    # Signature verification
    expected_signature = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        f"{order_id}|{payment_id}".encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(
        expected_signature,
        signature
    ):

        conn.close()

        return jsonify(
            success=False,
            message="Payment signature invalid hai."
        ), 400

    # Razorpay se payment status verify
    try:

        payment = razorpay_request(
            "GET",
            f"/payments/{payment_id}"
        )

    except Exception as error:

        conn.close()

        app.logger.error(
            "Payment status error: %s",
            error
        )

        return jsonify(
            success=False,
            message="Payment status verify nahi hua."
        ), 502

    if payment.get("order_id") != order_id:

        conn.close()

        return jsonify(
            success=False,
            message="Payment order mismatch."
        ), 400

    if payment.get("status") != "captured":

        conn.close()

        return jsonify(
            success=False,
            message="Payment abhi captured nahi hua."
        ), 400

    # PAYMENT SUCCESS
    conn.execute(
        """
        UPDATE orders
        SET
            status = 'paid',
            razorpay_payment_id = ?,
            razorpay_signature = ?
        WHERE id = ?
        """,
        (
            payment_id,
            signature,
            order["id"]
        )
    )

    conn.execute(
        """
        UPDATE users
        SET paid = 1
        WHERE id = ?
        """,
        (
            user["id"],
        )
    )

    conn.commit()
    conn.close()

    return jsonify(
        success=True,
        message="🎉 Premium activated!",
        user={
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "paid": True
        }
    )


# ==================================================
# START SERVER
# ==================================================

if __name__ == "__main__":

    init_db()

    print("🚀 Server: http://127.0.0.1:5000")
    print(
        "💰 Premium Price:",
        PRICE,
        "paise"
    )

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False
    )
