"""
Pukku Pankki — yksinkertainen pankkiprototyyppi
Valuutta: pukku (1 pukku = 100 senttiä)
"""

import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    flash,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash

# template_folder="." → HTML-tiedostot voivat olla suoraan juuressa
app = Flask(__name__, template_folder=".")
app.secret_key = os.environ.get("SECRET_KEY", "pukku-dev-secret-change-me-in-prod")

DB_PATH = Path(os.environ.get("DATABASE_PATH", "pukku.db"))


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT  NOT NULL,
            balance     INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user   INTEGER,
            to_user     INTEGER NOT NULL,
            amount      INTEGER NOT NULL CHECK (amount > 0),
            note        TEXT,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (from_user) REFERENCES users(id),
            FOREIGN KEY (to_user)   REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_user);
        CREATE INDEX IF NOT EXISTS idx_tx_to   ON transactions(to_user);
        """
    )
    db.commit()

    # Demo-käyttäjät jos tyhjä
    cur = db.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        demos = [
            ("alice", "alice123", 10_000),
            ("bob", "bob123", 5_000),
            ("carol", "carol123", 2_500),
        ]
        for username, pw, bal in demos:
            db.execute(
                "INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)",
                (username, generate_password_hash(pw), bal),
            )
        db.commit()
        print("Demo-käyttäjät luotu: alice/alice123, bob/bob123, carol/carol123")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def format_pukku(cents: int) -> str:
    euros = cents / 100
    return f"{euros:,.2f}".replace(",", "X").replace(".", ",").replace("X", " ") + " pukku"


# ---------- Auth ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""

        if not username or len(username) < 3:
            flash("Käyttäjänimen pitää olla vähintään 3 merkkiä.", "error")
            return render_template("register.html")
        if not password or len(password) < 6:
            flash("Salasanan pitää olla vähintään 6 merkkiä.", "error")
            return render_template("register.html")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), 1000),
            )
            db.commit()
            flash("Tili luotu! Voit kirjautua sisään.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Käyttäjänimi on jo käytössä.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Virheellinen käyttäjänimi tai salasana.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- Dashboard & Transfer ----------

@app.route("/")
@login_required
def dashboard():
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()

    txs = db.execute(
        """
        SELECT t.*,
               fu.username AS from_name,
               tu.username AS to_name
        FROM transactions t
        LEFT JOIN users fu ON t.from_user = fu.id
        JOIN users tu ON t.to_user = tu.id
        WHERE t.from_user = ? OR t.to_user = ?
        ORDER BY t.created_at DESC
        LIMIT 20
        """,
        (session["user_id"], session["user_id"]),
    ).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        balance_str=format_pukku(user["balance"]),
        transactions=txs,
        format_pukku=format_pukku,
    )


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    to_username = (request.form.get("to") or "").strip().lower()
    amount_str = (request.form.get("amount") or "").replace(",", ".").strip()
    note = (request.form.get("note") or "").strip()[:100]

    try:
        amount = float(amount_str)
        if amount <= 0:
            raise ValueError
        cents = int(round(amount * 100))
    except (ValueError, TypeError):
        flash("Anna kelvollinen summa (esim. 12,50).", "error")
        return redirect(url_for("dashboard"))

    if cents < 1:
        flash("Minimisumma on 0,01 pukku.", "error")
        return redirect(url_for("dashboard"))

    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")

        sender = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        receiver = db.execute(
            "SELECT * FROM users WHERE username = ?", (to_username,)
        ).fetchone()

        if not receiver:
            db.execute("ROLLBACK")
            flash("Vastaanottajaa ei löydy.", "error")
            return redirect(url_for("dashboard"))

        if receiver["id"] == sender["id"]:
            db.execute("ROLLBACK")
            flash("Et voi lähettää rahaa itsellesi.", "error")
            return redirect(url_for("dashboard"))

        if sender["balance"] < cents:
            db.execute("ROLLBACK")
            flash("Saldo ei riitä.", "error")
            return redirect(url_for("dashboard"))

        db.execute(
            "UPDATE users SET balance = balance - ? WHERE id = ?",
            (cents, sender["id"]),
        )
        db.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (cents, receiver["id"]),
        )
        db.execute(
            """
            INSERT INTO transactions (from_user, to_user, amount, note)
            VALUES (?, ?, ?, ?)
            """,
            (sender["id"], receiver["id"], cents, note or None),
        )
        db.commit()
        flash(f"Siirto onnistui: {format_pukku(cents)} → {receiver['username']}", "success")
    except Exception as e:
        db.execute("ROLLBACK")
        flash(f"Siirto epäonnistui: {e}", "error")

    return redirect(url_for("dashboard"))


# ---------- API ----------

@app.route("/api/balance")
@login_required
def api_balance():
    db = get_db()
    user = db.execute(
        "SELECT balance FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    return jsonify({
        "balance_cents": user["balance"],
        "balance": format_pukku(user["balance"]),
        "username": session["username"],
    })


@app.route("/api/transfer", methods=["POST"])
@login_required
def api_transfer():
    data = request.get_json(silent=True) or {}
    to_username = (data.get("to") or "").strip().lower()
    amount = data.get("amount")
    note = (data.get("note") or "")[:100]

    try:
        if isinstance(amount, (int, float)):
            cents = int(round(float(amount) * 100)) if amount < 10000 else int(amount)
        else:
            cents = int(round(float(str(amount).replace(",", ".")) * 100))
        if cents < 1:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "Virheellinen summa"}), 400

    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        sender = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        receiver = db.execute(
            "SELECT * FROM users WHERE username = ?", (to_username,)
        ).fetchone()

        if not receiver:
            db.execute("ROLLBACK")
            return jsonify({"error": "Käyttäjää ei löydy"}), 404
        if receiver["id"] == sender["id"]:
            db.execute("ROLLBACK")
            return jsonify({"error": "Et voi lähettää itsellesi"}), 400
        if sender["balance"] < cents:
            db.execute("ROLLBACK")
            return jsonify({"error": "Saldo ei riitä"}), 400

        db.execute(
            "UPDATE users SET balance = balance - ? WHERE id = ?",
            (cents, sender["id"]),
        )
        db.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (cents, receiver["id"]),
        )
        db.execute(
            "INSERT INTO transactions (from_user, to_user, amount, note) VALUES (?, ?, ?, ?)",
            (sender["id"], receiver["id"], cents, note or None),
        )
        db.commit()
        return jsonify({
            "status": "ok",
            "amount": format_pukku(cents),
            "to": receiver["username"],
        })
    except Exception as e:
        db.execute("ROLLBACK")
        return jsonify({"error": str(e)}), 500


# ---------- Startup ----------

@app.before_request
def ensure_db():
    if not hasattr(app, "_db_initialized"):
        init_db()
        app._db_initialized = True


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True, port=5000)185.199.108.153
