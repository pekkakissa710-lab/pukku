const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// --- Data-kansio ---
const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const usersFile = path.join(dataDir, "users.json");
const txsFile = path.join(dataDir, "transactions.json");

function loadJSON(file, fallback = []) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    console.error("Load error:", e.message);
  }
  return fallback;
}

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

let users = loadJSON(usersFile);
let transactions = loadJSON(txsFile);

// Demo-käyttäjät jos tyhjä (starting balance: 100 pukku = 10000 cents)
if (users.length === 0) {
  users = [
    { id: 1, username: "alice", password_hash: bcrypt.hashSync("alice123", 10), balance: 10000, created_at: new Date().toISOString() },
    { id: 2, username: "bob", password_hash: bcrypt.hashSync("bob123", 10), balance: 10000, created_at: new Date().toISOString() },
    { id: 3, username: "carol", password_hash: bcrypt.hashSync("carol123", 10), balance: 10000, created_at: new Date().toISOString() }
  ];
  saveJSON(usersFile, users);
  console.log("Demo-käyttäjät luotu with 100 pukku each");
}

let nextUserId = users.reduce((max, u) => Math.max(max, u.id), 0) + 1;
let nextTxId = transactions.reduce((max, t) => Math.max(max, t.id), 0) + 1;

// --- Middleware ---
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "pukku-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true }
}));

app.use(express.static(__dirname));

function formatPukku(cents) {
  return (cents / 100).toLocaleString("fi-FI", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  }) + " pukku";
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Kirjaudu sisään" });
  next();
}

// Health
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// Rekisteröinti
app.post("/api/register", (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (username.length < 3) return res.status(400).json({ error: "Käyttäjänimi liian lyhyt (min 3)" });
  if (password.length < 6) return res.status(400).json({ error: "Salasana liian lyhyt (min 6)" });
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: "Käyttäjänimi on jo käytössä" });
  }

  const user = {
    id: nextUserId++,
    username,
    password_hash: bcrypt.hashSync(password, 10),
    balance: 5000, // Uudet käyttäjät saavat 50 pukkua
    created_at: new Date().toISOString()
  };
  users.push(user);
  saveJSON(usersFile, users);
  res.json({ success: true, message: "Rekisteröinti onnistui! Kirjaudu sisään." });
});

// Kirjautuminen
app.post("/api/login", (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (!username || !password) {
    return res.status(400).json({ error: "Käyttäjänimi ja salasana vaaditaan" });
  }

  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Virheellinen käyttäjänimi tai salasana" });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ success: true, username: user.username, id: user.id });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Omat tiedot
app.get("/api/me", requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: "Kirjaudu sisään" });
  res.json({
    id: user.id,
    username: user.username,
    balance: user.balance,
    balanceStr: formatPukku(user.balance)
  });
});

// Käyttäjä ID:llä
app.get("/api/user/:id", requireAuth, (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id, 10));
  if (!user) return res.status(404).json({ error: "Käyttäjää ei löydy" });
  res.json({ id: user.id, username: user.username });
});

// Tapahtumat
app.get("/api/transactions", requireAuth, (req, res) => {
  const myId = req.session.userId;
  const txs = transactions
    .filter(t => t.from_user === myId || t.to_user === myId)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 30)
    .map(tx => {
      const fromUser = users.find(u => u.id === tx.from_user);
      const toUser = users.find(u => u.id === tx.to_user);
      return {
        ...tx,
        from_name: fromUser ? fromUser.username : null,
        to_name: toUser ? toUser.username : null,
        amountStr: formatPukku(tx.amount),
        isOut: tx.from_user === myId
      };
    });
  res.json(txs);
});

// Siirto
app.post("/api/transfer", requireAuth, (req, res) => {
  const toId = parseInt(req.body.toId, 10);
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

  if (!toId) return res.status(400).json({ error: "Vastaanottajan ID puuttuu" });

  const sender = users.find(u => u.id === req.session.userId);
  const receiver = users.find(u => u.id === toId);

  if (!receiver) return res.status(400).json({ error: "Vastaanottajaa ei löydy" });
  if (receiver.id === sender.id) return res.status(400).json({ error: "Et voi lähettää itsellesi" });
  if (sender.balance < cents) return res.status(400).json({ error: "Saldo ei riitä" });

  sender.balance -= cents;
  receiver.balance += cents;

  const tx = {
    id: nextTxId++,
    from_user: sender.id,
    to_user: receiver.id,
    amount: cents,
    note: note || null,
    created_at: new Date().toISOString()
  };
  transactions.push(tx);

  saveJSON(usersFile, users);
  saveJSON(txsFile, transactions);

  res.json({ success: true, message: "Siirto onnistui" });
});

app.listen(PORT, () => {
  console.log("Pukku Pankki käynnissä portissa " + PORT);
});
