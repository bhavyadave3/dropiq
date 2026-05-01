import os
import uuid
import time
import threading
from functools import wraps
from flask import Flask, render_template, request, redirect, abort, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeSerializer

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

serializer = URLSafeSerializer(app.secret_key)

# ================= SECURITY =================

@app.after_request
def headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

requests_log = {}

def rate_limit(limit=20, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            requests_log.setdefault(ip, [])
            requests_log[ip] = [t for t in requests_log[ip] if now - t < window]

            if len(requests_log[ip]) >= limit:
                return "Too many requests", 429

            requests_log[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ================= MODELS =================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

class File(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    filename = db.Column(db.String(200))
    token = db.Column(db.String(200))
    user_id = db.Column(db.Integer)
    is_guest = db.Column(db.Boolean)
    created_at = db.Column(db.Float)

class Text(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    content = db.Column(db.Text)
    token = db.Column(db.String(200))
    user_id = db.Column(db.Integer)
    is_guest = db.Column(db.Boolean)
    created_at = db.Column(db.Float)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ================= HELPERS =================

def allowed_file(filename):
    return '.' in filename


def generate_csrf():
    token = str(uuid.uuid4())
    session['csrf'] = token
    return token

def validate_csrf(token):
    return token == session.get("csrf")


# ================= ROUTES =================

@app.route("/dashboard")
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    texts = Text.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", files=files, texts=texts)


@app.route("/", methods=["GET","POST"])
@rate_limit()
def home():
    if request.method == "POST":

        if not validate_csrf(request.form.get("csrf")):
            return "CSRF error"

        file = request.files.get("file")

        if not file:
            return "No file"

        uid = str(uuid.uuid4())
        filename = uid + "_" + file.filename
        path = os.path.join(UPLOAD_FOLDER, filename)

        with open(path, "wb") as f:
            while True:
                chunk = file.stream.read(4096)
                if not chunk:
                    break
                f.write(chunk)

        token = serializer.dumps(uid)

        db.session.add(File(
            id=uid,
            filename=filename,
            token=token,
            user_id=current_user.id if current_user.is_authenticated else None,
            is_guest=not current_user.is_authenticated,
            created_at=time.time()
        ))
        db.session.commit()

        return f"<input value='/download/{token}' id='linkBox'><button onclick='copyLink()'>Copy</button>"

    return render_template("index.html", csrf=generate_csrf(), user=current_user)


@app.route("/download/<token>")
def download(token):
    try:
        fid = serializer.loads(token)
    except:
        return "Invalid link"

    file = File.query.get(fid)
    if not file:
        return "Invalid"

    expiry = 1800 if file.is_guest else 172800

    if time.time() - file.created_at > expiry:
        return "Expired"

    if not file.is_guest:
        if not current_user.is_authenticated or current_user.id != file.user_id:
            abort(403)

    return send_from_directory(UPLOAD_FOLDER, file.filename, as_attachment=True)


@app.route("/share_text", methods=["POST"])
def share_text():
    if not validate_csrf(request.form.get("csrf")):
        return "CSRF error"

    text = request.form.get("text")

    uid = str(uuid.uuid4())
    token = serializer.dumps(uid)

    db.session.add(Text(
        id=uid,
        content=text,
        token=token,
        user_id=current_user.id if current_user.is_authenticated else None,
        is_guest=not current_user.is_authenticated,
        created_at=time.time()
    ))
    db.session.commit()

    return f"<input value='/text/{token}' id='linkBox'><button onclick='copyLink()'>Copy</button>"


@app.route("/text/<token>")
def view_text(token):
    try:
        tid = serializer.loads(token)
    except:
        return "Invalid"

    text = Text.query.get(tid)
    if not text:
        return "Invalid"

    return f"<pre>{text.content}</pre>"


# ================= AUTH =================

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()

        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect("/")

        return "Invalid"

    return render_template("login.html")


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        db.session.add(User(
            username=request.form["username"],
            password=generate_password_hash(request.form["password"])
        ))
        db.session.commit()
        return redirect("/login")

    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


# ================= RUN =================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

    app.run(debug=True)
