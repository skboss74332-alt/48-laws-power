import os, json, sqlite3, base64, hashlib, hmac, urllib.request
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from laws_data import LAWS

app=Flask(__name__,static_folder=".",static_url_path="")
app.secret_key=os.environ.get("FLASK_SECRET_KEY","")
if not app.secret_key: raise RuntimeError("FLASK_SECRET_KEY set karo")
DB=os.environ.get("DB_PATH","users.db")
PRICE=int(os.environ.get("PREMIUM_PRICE_PAISE","9900"))
RP_ID=os.environ.get("RAZORPAY_KEY_ID","")
RP_SECRET=os.environ.get("RAZORPAY_KEY_SECRET","")
WEBHOOK_SECRET=os.environ.get("RAZORPAY_WEBHOOK_SECRET","")
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE","0")=="1")

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=db()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,paid INTEGER DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS orders(
      id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,
      razorpay_order_id TEXT UNIQUE NOT NULL,amount INTEGER NOT NULL,
      currency TEXT NOT NULL DEFAULT 'INR',status TEXT NOT NULL DEFAULT 'created',
      razorpay_payment_id TEXT UNIQUE,razorpay_signature TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    c.commit(); c.close()

def current_user():
    uid=session.get("user_id")
    if not uid:return None
    c=db(); u=c.execute("SELECT id,name,email,paid FROM users WHERE id=?",(uid,)).fetchone(); c.close()
    if not u: session.clear()
    return u

def login_required(fn):
    @wraps(fn)
    def w(*a,**k):
        if not current_user():return jsonify(success=False,message="Login required"),401
        return fn(*a,**k)
    return w

def rp(method,path,payload=None):
    if not RP_ID or not RP_SECRET: raise RuntimeError("Razorpay keys missing")
    token=base64.b64encode(f"{RP_ID}:{RP_SECRET}".encode()).decode()
    body=None if payload is None else json.dumps(payload).encode()
    r=urllib.request.Request("https://api.razorpay.com/v1"+path,data=body,method=method)
    r.add_header("Authorization","Basic "+token);r.add_header("Content-Type","application/json")
    with urllib.request.urlopen(r,timeout=20) as x:return json.loads(x.read().decode())

@app.get("/")
def home():return send_from_directory(".","index.html")

@app.post("/api/register")
def register():
    d=request.get_json(silent=True) or {}; name=str(d.get("name","")).strip()
    email=str(d.get("email","")).strip().lower(); pw=str(d.get("password",""))
    if not name or not email or not pw:return jsonify(success=False,message="Sabhi fields bharo"),400
    if len(pw)<6:return jsonify(success=False,message="Password kam se kam 6 characters ka hona chahiye"),400
    c=db()
    try:c.execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",(name,email,generate_password_hash(pw)));c.commit()
    except sqlite3.IntegrityError:c.close();return jsonify(success=False,message="Ye email already registered hai"),409
    c.close();return jsonify(success=True,message="Registration successful")

@app.post("/api/login")
def login():
    d=request.get_json(silent=True) or {};email=str(d.get("email","")).strip().lower();pw=str(d.get("password",""))
    c=db();u=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone();c.close()
    if not u or not check_password_hash(u["password"],pw):return jsonify(success=False,message="Email ya password galat hai"),401
    session.clear();session["user_id"]=u["id"]
    return jsonify(success=True,message="Login successful",user={"name":u["name"],"email":u["email"],"paid":bool(u["paid"])})

@app.get("/api/me")
def me():
    u=current_user()
    if not u:return jsonify(logged_in=False)
    return jsonify(logged_in=True,user={"name":u["name"],"email":u["email"],"paid":bool(u["paid"])})

@app.get("/api/logout")
def logout():session.clear();return jsonify(success=True,message="Logout successful")

@app.get("/api/law/<int:number>")
@login_required
def law(number):
    if number not in LAWS:return jsonify(success=False,message="Law পাওয়া যায়নি"),404
    u=current_user()
    if number>=6 and not u["paid"]:return jsonify(success=False,message="Premium required"),403
    return jsonify(success=True,law=LAWS[number])

@app.post("/api/create-order")
@login_required
def create_order():
    u=current_user()
    if u["paid"]:return jsonify(success=False,message="Premium already active"),400
    if not RP_ID or not RP_SECRET:return jsonify(success=False,message="Razorpay Test Keys configure nahi kiye gaye."),503
    try:
        o=rp("POST","/orders",{"amount":PRICE,"currency":"INR",
          "receipt":f"premium_{u['id']}_{os.urandom(5).hex()}",
          "notes":{"user_id":str(u["id"]),"plan":"premium_lifetime"},"capture":"automatic"})
        c=db();c.execute("INSERT INTO orders(user_id,razorpay_order_id,amount,currency) VALUES(?,?,?,?)",
                         (u["id"],o["id"],o["amount"],o["currency"]));c.commit();c.close()
        return jsonify(success=True,key_id=RP_ID,order_id=o["id"],amount=o["amount"],currency=o["currency"],
                       user={"name":u["name"],"email":u["email"]})
    except Exception as e:
        app.logger.error("order error: %s",e);return jsonify(success=False,message="Razorpay order create nahi hua."),502

@app.post("/api/verify-payment")
@login_required
def verify_payment():
    d=request.get_json(silent=True) or {};pid=str(d.get("razorpay_payment_id",""))
    oid=str(d.get("razorpay_order_id",""));sig=str(d.get("razorpay_signature",""))
    if not pid or not oid or not sig:return jsonify(success=False,message="Payment response incomplete hai."),400
    u=current_user();c=db();o=c.execute("SELECT * FROM orders WHERE razorpay_order_id=? AND user_id=?",(oid,u["id"])).fetchone()
    if not o:c.close();return jsonify(success=False,message="Order verify nahi hua."),400
    if o["razorpay_payment_id"]:c.close();return jsonify(success=False,message="Payment already processed."),409
    expected=hmac.new(RP_SECRET.encode(),f"{oid}|{pid}".encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,sig):c.close();return jsonify(success=False,message="Payment signature invalid hai."),400
    try:p=rp("GET",f"/payments/{pid}")
    except Exception as e:
        c.close();app.logger.error("status error: %s",e)
        return jsonify(success=False,message="Payment status verify nahi hua."),502
    if p.get("order_id")!=oid or p.get("status")!="captured":
        c.close();return jsonify(success=False,message="Payment abhi captured nahi hua."),400
    c.execute("UPDATE orders SET status='paid',razorpay_payment_id=?,razorpay_signature=? WHERE id=?",(pid,sig,o["id"]))
    c.execute("UPDATE users SET paid=1 WHERE id=?",(u["id"],));c.commit();c.close()
    return jsonify(success=True,message="🎉 Premium activated!",user={"name":u["name"],"email":u["email"],"paid":True})

@app.post("/api/razorpay/webhook")
def webhook():
    if not WEBHOOK_SECRET:return "",200
    raw=request.get_data();received=request.headers.get("X-Razorpay-Signature","")
    expected=hmac.new(WEBHOOK_SECRET.encode(),raw,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,received):return "invalid signature",400
    d=request.get_json(silent=True) or {}
    if d.get("event")=="payment.captured":
        e=d.get("payload",{}).get("payment",{}).get("entity",{})
        pid,oid=e.get("id"),e.get("order_id")
        if pid and oid:
            c=db();o=c.execute("SELECT * FROM orders WHERE razorpay_order_id=?",(oid,)).fetchone()
            if o and not o["razorpay_payment_id"]:
                c.execute("UPDATE orders SET status='paid',razorpay_payment_id=? WHERE id=?",(pid,o["id"]))
                c.execute("UPDATE users SET paid=1 WHERE id=?",(o["user_id"],));c.commit()
            c.close()
    return "",200

init_db()

if __name__=="__main__":
    print("🚀 http://127.0.0.1:5000")
    app.run(host="127.0.0.1",port=5000,debug=False)
