const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// --- Tietokanta ---
const db = new Database("pukku.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user INTEGER,
    to_user INTEGER NOT NULL,
    amount INTEGER NOT NULL CHECK (amount > 0),
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (from_user) REFERENCES users(id),
    FOREIGN KEY (to_user) REFERENCES users(id)
  );
`);

// Demo-käyttäjät
const count = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
if (count === 0) {
  const insert = db.prepare("INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)");
  [
    ["alice", "alice123", 10000],
    ["bob", "bob123", 5000],
    ["carol", "carol123", 2500]
  ].forEach(([u, p, b]) => insert.run(u, bcrypt.hashSync(p, 10), b));
  console.log("Demo-käyttäjät luotu");
}

// --- Middleware ---
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "pukku-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Staattiset HTML-tiedostot juuresta
app.use(express.static(__dirname));

// --- Apufunktiot ---
function formatPukku(cents) {
  return (cents / 100).toLocaleString("fi-FI", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  }) + " pukku";
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Kirjaudu sisään" });
  }
  next();
}

// --- API ---

// Rekisteröinti
app.post("/api/register", (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (username.length < 3) return res.status(400).json({ error: "Käyttäjänimi liian lyhyt" });
  if (password.length < 6) return res.status(400).json({ error: "Salasana liian lyhyt" });

  try {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)").run(username, hash, 1000);
    res.json({ success: true, message: "Tili luotu" });
  } catch {
    res.status(400).json({ error: "Käyttäjänimi on jo käytössä" });
  }
});

// Kirjautuminen
app.post("/api/login", (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  const password = req.body.password || "";

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(400).json({ error: "Virheellinen käyttäjänimi tai salasana" });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ success: true, username: user.username });
});

// Uloskirjautuminen
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Saldo + käyttäjäinfo
app.get("/api/me", requireAuth, (req, res) => {
  const user = db.prepare("SELECT id, username, balance FROM users WHERE id = ?").get(req.session.userId);
  res.json({
    username: user.username,
    balance: user.balance,
    balanceStr: formatPukku(user.balance)
  });
});

// Tapahtumat
app.get("/api/transactions", requireAuth, (req, res) => {
  const txs = db.prepare(`
    SELECT t.*, fu.username AS from_name, tu.username AS to_name
    FROM transactions t
    LEFT JOIN users fu ON t.from_user = fu.id
    JOIN users tu ON t.to_user = tu.id
    WHERE t.from_user = ? OR t.to_user = ?
    ORDER BY t.created_at DESC
    LIMIT 30
  `).all(req.session.userId, req.session.userId);

  res.json(txs.map(tx => ({
    ...tx,
    amountStr: formatPukku(tx.amount),
    isOut: tx.from_user === req.session.userId
  })));
});

// Siirto
app.post("/api/transfer", requireAuth, (req, res) => {
  const to = (req.body.to || "").trim().toLowerCase();
  const note = (req.body.note || "").trim().slice(0, 100);
  let cents;

  try {
    const amount = parseFloat(String(req.body.amount).replace(",", "."));
    if (isNaN(amount) || amount <= 0) throw new Error();
    cents = Math.round(amount * 100);
    if (cents < 1) throw new Error();
  } catch {
    return res.status(400).json({ error: "Virheellinen summa" });
  }

  try {
    const transfer = db.transaction(() => {
      const sender = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
      const receiver = db.prepare("SELECT * FROM users WHERE username = ?").get(to);

      if (!receiver) throw new Error("Vastaanottajaa ei löydy");
      if (receiver.id === sender.id) throw new Error("Et voi lähettää itsellesi");
      if (sender.balance < cents) throw new Error("Saldo ei riitä");

      db.prepare("UPDATE users SET balance = balance - ? WHERE id = ?").run(cents, sender.id);
      db.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").run(cents, receiver.id);
      db.prepare("INSERT INTO transactions (from_user, to_user, amount, note) VALUES (?, ?, ?, ?)")
        .run(sender.id, receiver.id, cents, note || null);
    });

    transfer();
    res.json({ success: true, message: "Siirto onnistui" });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Käynnistys
app.listen(PORT, () => {
  console.log("Pukku Pankki käynnissä portissa " + PORT);
});
