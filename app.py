import os
import uuid
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, abort, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeSerializer

# ================= INIT =================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

serializer = URLSafeSerializer(app.secret_key)

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

def generate_csrf():
    token = str(uuid.uuid4())
    session['csrf'] = token
    return token

def validate_csrf(token):
    return token == session.get("csrf")

# ================= ROUTES =================

@app.route("/", methods=["GET","POST"])
def home():
    if request.method == "POST":

        if not validate_csrf(request.form.get("csrf")):
            return "CSRF error"

        file = request.files.get("file")

        if not file:
            return "No file"

        uid = str(uuid.uuid4())
        filename = uid + "_" + file.filename
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        file.save(path)

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

        return f"<input value='/download/{token}' id='linkBox'>"

    return render_template("index.html", csrf=generate_csrf())

@app.route("/download/<token>")
def download(token):
    try:
        fid = serializer.loads(token)
    except:
        return "Invalid link"

    file = File.query.get(fid)
    if not file:
        return "Invalid"

    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)

# ================= AUTH =================

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()

        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect("/")

        return "Invalid credentials"

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

# ================= INIT DB =================

with app.app_context():
    db.create_all()

# ================= RUN =================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
