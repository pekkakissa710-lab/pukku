const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SECRET_KEY;

if (!SESSION_SECRET) {
  console.error(
    "ERROR: SECRET_KEY environment variable is missing."
  );
  process.exit(1);
}

/*
|--------------------------------------------------------------------------
| CORS
|--------------------------------------------------------------------------
*/

const allowedOrigins = [
  "https://pukku.my.to",
  "https://www.pukku.my.to",
  "https://pukku-1.onrender.com"
];

app.use(
  cors({
    origin(origin, callback) {
      // Requests without an Origin header
      // are allowed (health checks, server-to-server, etc.)
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      console.warn(
        `Blocked CORS origin: ${origin}`
      );

      return callback(
        new Error("CORS origin not allowed")
      );
    },

    credentials: true,

    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);

/*
|--------------------------------------------------------------------------
| Body parsing
|--------------------------------------------------------------------------
*/

app.use(
  express.json({
    limit: "32kb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "32kb"
  })
);

/*
|--------------------------------------------------------------------------
| Proxy
|--------------------------------------------------------------------------
*/

app.set(
  "trust proxy",
  1
);

/*
|--------------------------------------------------------------------------
| Session
|--------------------------------------------------------------------------
*/

app.use(
  session({
    name: "pukku.sid",

    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    proxy: true,

    cookie: {
      httpOnly: true,

      secure: true,

      sameSite: "none",

      maxAge:
        7 * 24 * 60 * 60 * 1000
    }
  })
);

/*
|--------------------------------------------------------------------------
| Data files
|--------------------------------------------------------------------------
*/

const DATA_DIR =
  path.join(
    __dirname,
    "data"
  );

const USERS_FILE =
  path.join(
    DATA_DIR,
    "users.json"
  );

const TRANSACTIONS_FILE =
  path.join(
    DATA_DIR,
    "transactions.json"
  );

if (
  !fs.existsSync(DATA_DIR)
) {
  fs.mkdirSync(
    DATA_DIR,
    {
      recursive: true
    }
  );
}

/*
|--------------------------------------------------------------------------
| JSON helpers
|--------------------------------------------------------------------------
*/

function loadJSON(
  file,
  fallback
) {
  try {
    if (
      !fs.existsSync(file)
    ) {
      return fallback;
    }

    const raw =
      fs.readFileSync(
        file,
        "utf8"
      );

    if (!raw.trim()) {
      return fallback;
    }

    const parsed =
      JSON.parse(raw);

    return parsed;
  } catch (error) {
    console.error(
      `Failed to load ${file}:`,
      error.message
    );

    return fallback;
  }
}

function saveJSON(
  file,
  data
) {
  const temporary =
    `${file}.tmp`;

  fs.writeFileSync(
    temporary,
    JSON.stringify(
      data,
      null,
      2
    ),
    "utf8"
  );

  fs.renameSync(
    temporary,
    file
  );
}

/*
|--------------------------------------------------------------------------
| Load data
|--------------------------------------------------------------------------
*/

let users =
  loadJSON(
    USERS_FILE,
    []
  );

let transactions =
  loadJSON(
    TRANSACTIONS_FILE,
    []
  );

if (!Array.isArray(users)) {
  users = [];
}

if (!Array.isArray(transactions)) {
  transactions = [];
}

/*
|--------------------------------------------------------------------------
| Prototype demo users
|--------------------------------------------------------------------------
*/

if (users.length === 0) {
  users = [
    {
      id: 1,

      username: "alice",

      password_hash:
        bcrypt.hashSync(
          "alice123",
          10
        ),

      balance: 10000,

      created_at:
        new Date().toISOString()
    },

    {
      id: 2,

      username: "bob",

      password_hash:
        bcrypt.hashSync(
          "bob123",
          10
        ),

      balance: 10000,

      created_at:
        new Date().toISOString()
    },

    {
      id: 3,

      username: "carol",

      password_hash:
        bcrypt.hashSync(
          "carol123",
          10
        ),

      balance: 10000,

      created_at:
        new Date().toISOString()
    }
  ];

  saveJSON(
    USERS_FILE,
    users
  );

  console.log(
    "Prototype demo users created"
  );
}

/*
|--------------------------------------------------------------------------
| IDs
|--------------------------------------------------------------------------
*/

let nextUserId =
  users.reduce(
    (
      maximum,
      user
    ) =>
      Math.max(
        maximum,
        Number(user.id) || 0
      ),
    0
  ) + 1;

let nextTransactionId =
  transactions.reduce(
    (
      maximum,
      transaction
    ) =>
      Math.max(
        maximum,
        Number(transaction.id) || 0
      ),
    0
  ) + 1;

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function formatPukku(
  cents
) {
  return (
    (
      cents / 100
    ).toLocaleString(
      "fi-FI",
      {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
      }
    ) +
    " pukku"
  );
}

function requireAuth(
  req,
  res,
  next
) {
  if (!req.session.userId) {
    return res
      .status(401)
      .json({
        error:
          "Kirjaudu sisään"
      });
  }

  next();
}

/*
|--------------------------------------------------------------------------
| Health
|--------------------------------------------------------------------------
*/

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      status: "ok",

      time:
        new Date().toISOString()
    });
  }
);

/*
|--------------------------------------------------------------------------
| Register
|--------------------------------------------------------------------------
*/

app.post(
  "/api/register",
  (req, res) => {
    const username =
      String(
        req.body.username || ""
      )
        .trim()
        .toLowerCase();

    const password =
      String(
        req.body.password || ""
      );

    if (
      !/^[a-z0-9_]{3,24}$/.test(
        username
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "Käyttäjänimi: 3–24 merkkiä, vain a-z, 0-9 ja _"
        });
    }

    if (
      password.length < 6 ||
      password.length > 128
    ) {
      return res
        .status(400)
        .json({
          error:
            "Salasanan pitää olla 6–128 merkkiä"
        });
    }

    const exists =
      users.some(
        user =>
          user.username ===
          username
      );

    if (exists) {
      return res
        .status(400)
        .json({
          error:
            "Käyttäjänimi on jo käytössä"
        });
    }

    const user = {
      id:
        nextUserId++,

      username,

      password_hash:
        bcrypt.hashSync(
          password,
          10
        ),

      balance: 5000,

      created_at:
        new Date().toISOString()
    };

    users.push(user);

    try {
      saveJSON(
        USERS_FILE,
        users
      );
    } catch (error) {
      console.error(
        "Failed to save user:",
        error.message
      );

      users.pop();

      nextUserId--;

      return res
        .status(500)
        .json({
          error:
            "Tilin tallentaminen epäonnistui"
        });
    }

    res.json({
      success: true,

      message:
        "Tili luotu!"
    });
  }
);

/*
|--------------------------------------------------------------------------
| Login
|--------------------------------------------------------------------------
*/

app.post(
  "/api/login",
  (req, res) => {
    const username =
      String(
        req.body.username || ""
      )
        .trim()
        .toLowerCase();

    const password =
      String(
        req.body.password || ""
      );

    if (
      !username ||
      !password
    ) {
      return res
        .status(400)
        .json({
          error:
            "Käyttäjänimi ja salasana vaaditaan"
        });
    }

    const user =
      users.find(
        item =>
          item.username ===
          username
      );

    if (
      !user ||
      !bcrypt.compareSync(
        password,
        user.password_hash
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            "Virheellinen käyttäjänimi tai salasana"
        });
    }

    req.session.regenerate(
      error => {
        if (error) {
          console.error(
            "Session regeneration error:",
            error.message
          );

          return res
            .status(500)
            .json({
              error:
                "Istunnon luominen epäonnistui"
            });
        }

        req.session.userId =
          user.id;

        req.session.username =
          user.username;

        req.session.save(
          saveError => {
            if (saveError) {
              console.error(
                "Session save error:",
                saveError.message
              );

              return res
                .status(500)
                .json({
                  error:
                    "Istunnon tallentaminen epäonnistui"
                });
            }

            res.json({
              success: true,

              username:
                user.username,

              id:
                user.id
            });
          }
        );
      }
    );
  }
);

/*
|--------------------------------------------------------------------------
| Logout
|--------------------------------------------------------------------------
*/

app.post(
  "/api/logout",
  (req, res) => {
    req.session.destroy(
      error => {
        if (error) {
          console.error(
            "Logout error:",
            error.message
          );
        }

        res.clearCookie(
          "pukku.sid",
          {
            httpOnly: true,

            secure: true,

            sameSite: "none"
          }
        );

        res.json({
          success: true
        });
      }
    );
  }
);

/*
|--------------------------------------------------------------------------
| Current user
|--------------------------------------------------------------------------
*/

app.get(
  "/api/me",
  requireAuth,
  (req, res) => {
    const user =
      users.find(
        item =>
          item.id ===
          req.session.userId
      );

    if (!user) {
      return req.session.destroy(
        () => {
          res
            .status(401)
            .json({
              error:
                "Kirjaudu sisään"
            });
        }
      );
    }

    res.json({
      id:
        user.id,

      username:
        user.username,

      balance:
        user.balance,

      balanceStr:
        formatPukku(
          user.balance
        )
    });
  }
);

/*
|--------------------------------------------------------------------------
| User lookup
|--------------------------------------------------------------------------
*/

app.get(
  "/api/user/:id",
  requireAuth,
  (req, res) => {
    const id =
      Number.parseInt(
        req.params.id,
        10
      );

    if (
      !Number.isSafeInteger(id) ||
      id < 1
    ) {
      return res
        .status(400)
        .json({
          error:
            "Virheellinen käyttäjä-ID"
        });
    }

    const user =
      users.find(
        item =>
          item.id === id
      );

    if (!user) {
      return res
        .status(404)
        .json({
          error:
            "Käyttäjää ei löydy"
        });
    }

    res.json({
      id:
        user.id,

      username:
        user.username
    });
  }
);

/*
|--------------------------------------------------------------------------
| Transactions
|--------------------------------------------------------------------------
*/

app.get(
  "/api/transactions",
  requireAuth,
  (req, res) => {
    const myId =
      req.session.userId;

    const result =
      transactions
        .filter(
          transaction =>
            transaction.from_user ===
              myId ||
            transaction.to_user ===
              myId
        )
        .sort(
          (a, b) =>
            new Date(
              b.created_at
            ).getTime() -
            new Date(
              a.created_at
            ).getTime()
        )
        .slice(0, 30)
        .map(
          transaction => {
            const fromUser =
              users.find(
                user =>
                  user.id ===
                  transaction.from_user
              );

            const toUser =
              users.find(
                user =>
                  user.id ===
                  transaction.to_user
              );

            return {
              id:
                transaction.id,

              from_user:
                transaction.from_user,

              to_user:
                transaction.to_user,

              from_name:
                fromUser
                  ? fromUser.username
                  : null,

              to_name:
                toUser
                  ? toUser.username
                  : null,

              amount:
                transaction.amount,

              amountStr:
                formatPukku(
                  transaction.amount
                ),

              note:
                transaction.note,

              created_at:
                transaction.created_at,

              isOut:
                transaction.from_user ===
                myId
            };
          }
        );

    res.json(result);
  }
);

/*
|--------------------------------------------------------------------------
| Transfer
|--------------------------------------------------------------------------
*/

app.post(
  "/api/transfer",
  requireAuth,
  (req, res) => {
    const toId =
      Number.parseInt(
        req.body.toId,
        10
      );

    const rawAmount =
      String(
        req.body.amount ?? ""
      ).replace(
        ",",
        "."
      );

    const amount =
      Number(rawAmount);

    const note =
      String(
        req.body.note || ""
      )
        .trim()
        .slice(0, 100);

    if (
      !Number.isSafeInteger(
        toId
      ) ||
      toId < 1
    ) {
      return res
        .status(400)
        .json({
          error:
            "Vastaanottajan ID puuttuu"
        });
    }

    if (
      !Number.isFinite(
        amount
      ) ||
      amount <= 0 ||
      amount > 999999.99
    ) {
      return res
        .status(400)
        .json({
          error:
            "Virheellinen summa"
        });
    }

    const cents =
      Math.round(
        amount * 100
      );

    if (
      !Number.isSafeInteger(
        cents
      ) ||
      cents < 1
    ) {
      return res
        .status(400)
        .json({
          error:
            "Virheellinen summa"
        });
    }

    const sender =
      users.find(
        user =>
          user.id ===
          req.session.userId
      );

    const receiver =
      users.find(
        user =>
          user.id ===
          toId
      );

    if (!sender) {
      return res
        .status(401)
        .json({
          error:
            "Kirjaudu sisään"
        });
    }

    if (!receiver) {
      return res
        .status(400)
        .json({
          error:
            "Vastaanottajaa ei löydy"
        });
    }

    if (
      receiver.id ===
      sender.id
    ) {
      return res
        .status(400)
        .json({
          error:
            "Et voi lähettää itsellesi"
        });
    }

    if (
      sender.balance <
      cents
    ) {
      return res
        .status(400)
        .json({
          error:
            "Saldo ei riitä"
        });
    }

    sender.balance -=
      cents;

    receiver.balance +=
      cents;

    const transaction = {
      id:
        nextTransactionId++,

      from_user:
        sender.id,

      to_user:
        receiver.id,

      amount:
        cents,

      note:
        note || null,

      created_at:
        new Date().toISOString()
    };

    transactions.push(
      transaction
    );

    try {
      saveJSON(
        USERS_FILE,
        users
      );

      saveJSON(
        TRANSACTIONS_FILE,
        transactions
      );
    } catch (error) {
      console.error(
        "Transfer save error:",
        error.message
      );

      sender.balance +=
        cents;

      receiver.balance -=
        cents;

      transactions.pop();

      nextTransactionId--;

      return res
        .status(500)
        .json({
          error:
            "Siirron tallennus epäonnistui"
        });
    }

    res.json({
      success: true,

      message:
        "Siirto onnistui",

      amount:
        cents,

      amountStr:
        formatPukku(
          cents
        )
    });
  }
);

/*
|--------------------------------------------------------------------------
| API 404
|--------------------------------------------------------------------------
*/

app.use(
  "/api",
  (req, res) => {
    res
      .status(404)
      .json({
        error:
          "API endpoint not found"
      });
  }
);

/*
|--------------------------------------------------------------------------
| Start
|--------------------------------------------------------------------------
*/

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Pukku server running on port ${PORT}`
    );
  }
);
