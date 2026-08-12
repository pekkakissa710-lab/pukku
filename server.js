const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const usersFile = path.join(dataDir, "users.json");
const txsFile = path.join(dataDir, "transactions.json");

function loadJSON(file, fallback = []) {
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, "utf8"));
    }
  } catch (error) {
    console.error("Load error:", error.message);
  }
  return fallback;
}

function saveJSON(file, data) {
  const tempFile = `${file}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), "utf8");
  fs.renameSync(tempFile, file);
}

let users = loadJSON(usersFile);
let transactions = loadJSON(txsFile);

if (users.length === 0) {
  users = [
    {
      id: 1,
      username: "alice",
      password_hash: bcrypt.hashSync("alice123", 10),
      balance: 10000,
      created_at: new Date().toISOString()
    },
    {
      id: 2,
      username: "bob",
      password_hash: bcrypt.hashSync("bob123", 10),
      balance: 10000,
      created_at: new Date().toISOString()
    },
    {
      id: 3,
      username: "carol",
      password_hash: bcrypt.hashSync("carol123", 10),
      balance: 10000,
      created_at: new Date().toISOString()
    }
  ];

  saveJSON(usersFile, users);
  console.log("Prototype demo users created");
}

let nextUserId =
  users.reduce((max, user) => Math.max(max, Number(user.id) || 0), 0) + 1;

let nextTxId =
  transactions.reduce((max, tx) => Math.max(max, Number(tx.id) || 0), 0) + 1;

app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: true, limit: "32kb" }));

function readSessionSecret() {
  if (process.env.SESSION_SECRET) {
    return process.env.SESSION_SECRET.trim();
  }

  const secretFile =
    process.env.SESSION_SECRET_FILE || "/etc/secrets/SECRET_KEY";

  try {
    const secret = fs.readFileSync(secretFile, "utf8").trim();

    if (secret) {
      return secret;
    }
  } catch {
    console.warn(`Could not read session secret from ${secretFile}`);
  }

  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "No session secret configured. Set SESSION_SECRET or use /etc/secrets/SECRET_KEY."
    );
  }

  console.warn("Using development-only session secret");
  return "pukku-development-secret";
}

const sessionSecret = readSessionSecret();
const isProduction = process.env.NODE_ENV === "production";

app.set("trust proxy", 1);

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction
    }
  })
);

app.use(express.static(__dirname, { extensions: ["html"] }));

function formatPukku(cents) {
  return (
    (cents / 100).toLocaleString("fi-FI", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }) + " pukku"
  );
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Kirjaudu sisään"
    });
  }

  next();
}

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    time: new Date().toISOString()
  });
});

app.post("/api/register", (req, res) => {
  const username = String(req.body.username || "")
    .trim()
    .toLowerCase();

  const password = String(req.body.password || "");

  if (!/^[a-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({
      error: "Käyttäjänimi: 3–24 merkkiä, vain a-z, 0-9 ja _"
    });
  }

  if (password.length < 6 || password.length > 128) {
    return res.status(400).json({
      error: "Salasanan pitää olla 6–128 merkkiä"
    });
  }

  if (users.some(user => user.username === username)) {
    return res.status(400).json({
      error: "Käyttäjänimi on jo käytössä"
    });
  }

  const user = {
    id: nextUserId++,
    username,
    password_hash: bcrypt.hashSync(password, 10),
    balance: 5000,
    created_at: new Date().toISOString()
  };

  users.push(user);
  saveJSON(usersFile, users);

  res.json({
    success: true,
    message: "Tili luotu!"
  });
});

app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "")
    .trim()
    .toLowerCase();

  const password = String(req.body.password || "");

  if (!username || !password) {
    return res.status(400).json({
      error: "Käyttäjänimi ja salasana vaaditaan"
    });
  }

  const user = users.find(item => item.username === username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({
      error: "Virheellinen käyttäjänimi tai salasana"
    });
  }

  req.session.regenerate(error => {
    if (error) {
      return res.status(500).json({
        error: "Istunnon luominen epäonnistui"
      });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      username: user.username,
      id: user.id
    });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");

    res.json({
      success: true
    });
  });
});

app.get("/api/me", requireAuth, (req, res) => {
  const user = users.find(item => item.id === req.session.userId);

  if (!user) {
    req.session.destroy(() => {});

    return res.status(401).json({
      error: "Kirjaudu sisään"
    });
  }

  res.json({
    id: user.id,
    username: user.username,
    balance: user.balance,
    balanceStr: formatPukku(user.balance)
  });
});

app.get("/api/user/:id", requireAuth, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({
      error: "Virheellinen käyttäjä-ID"
    });
  }

  const user = users.find(item => item.id === id);

  if (!user) {
    return res.status(404).json({
      error: "Käyttäjää ei löydy"
    });
  }

  res.json({
    id: user.id,
    username: user.username
  });
});

app.get("/api/transactions", requireAuth, (req, res) => {
  const myId = req.session.userId;

  const txs = transactions
    .filter(tx => tx.from_user === myId || tx.to_user === myId)
    .sort(
      (a, b) =>
        new Date(b.created_at).getTime() -
        new Date(a.created_at).getTime()
    )
    .slice(0, 30)
    .map(tx => {
      const fromUser = users.find(user => user.id === tx.from_user);
      const toUser = users.find(user => user.id === tx.to_user);

      return {
        id: tx.id,
        from_user: tx.from_user,
        to_user: tx.to_user,
        from_name: fromUser ? fromUser.username : null,
        to_name: toUser ? toUser.username : null,
        amount: tx.amount,
        amountStr: formatPukku(tx.amount),
        note: tx.note,
        created_at: tx.created_at,
        isOut: tx.from_user === myId
      };
    });

  res.json(txs);
});

app.post("/api/transfer", requireAuth, (req, res) => {
  const toId = Number.parseInt(req.body.toId, 10);
  const rawAmount = String(req.body.amount ?? "").replace(",", ".");
  const amount = Number(rawAmount);
  const note = String(req.body.note || "").trim().slice(0, 100);

  if (!Number.isSafeInteger(toId) || toId < 1) {
    return res.status(400).json({
      error: "Vastaanottajan ID puuttuu"
    });
  }

  if (!Number.isFinite(amount) || amount <= 0 || amount > 999999.99) {
    return res.status(400).json({
      error: "Virheellinen summa"
    });
  }

  const cents = Math.round(amount * 100);

  if (!Number.isSafeInteger(cents) || cents < 1) {
    return res.status(400).json({
      error: "Virheellinen summa"
    });
  }

  const sender = users.find(user => user.id === req.session.userId);
  const receiver = users.find(user => user.id === toId);

  if (!sender) {
    return res.status(401).json({
      error: "Kirjaudu sisään"
    });
  }

  if (!receiver) {
    return res.status(400).json({
      error: "Vastaanottajaa ei löydy"
    });
  }

  if (receiver.id === sender.id) {
    return res.status(400).json({
      error: "Et voi lähettää itsellesi"
    });
  }

  if (sender.balance < cents) {
    return res.status(400).json({
      error: "Saldo ei riitä"
    });
  }

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

  try {
    saveJSON(usersFile, users);
    saveJSON(txsFile, transactions);
  } catch (error) {
    console.error("Transfer save error:", error);

    sender.balance += cents;
    receiver.balance -= cents;
    transactions.pop();
    nextTxId--;

    return res.status(500).json({
      error: "Siirron tallennus epäonnistui"
    });
  }

  res.json({
    success: true,
    message: "Siirto onnistui",
    amountStr: formatPukku(cents)
  });
});

app.listen(PORT, () => {
  console.log(`Pukku Pankki käynnissä portissa ${PORT}`);
});
