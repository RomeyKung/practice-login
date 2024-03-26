const cors = require("cors");
const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");

const port = 8000;

//setup express
const app = express();
app.use(express.json());

//setup cors กำหนดว่าเราอนุญาตให้ใครเข้ามาใช้งาน api ของเรา
app.use(
  cors({
    credentials: true,
    origin: ["http://localhost:8888"],
  })
);

//setup cookie and session
app.use(cookieParser());
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
  })
);

//setup jwt
const secret = "mysecret";

let conn = null;

// function init connection mysql
const initMySQL = async () => {
  conn = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "tutorial",
  });
};

/* เราจะแก้ไข code ที่อยู่ตรงกลาง */

// Listen
app.listen(port, async () => {
  await initMySQL();
  console.log("Server started at port 8000");
});

app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const salt = 10;
    const passwordHash = await bcrypt.hash(password, salt);

    const userData = {
      email: email,
      password: passwordHash,
    };
    // const salt = await bcrypt.genSalt(10);

    const [result] = await conn.query("INSERT INTO users SET ?", userData);
    res.json({
      message: "Register success",
      result,
    });
  } catch (err) {
    console.log(err);
    res.json({
      message: "Register failed",
      err,
    });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const [user] = await conn.query("SELECT * FROM users WHERE email = ?", [
    email,
  ]);
  if (user.length === 0) {
    res.status(400).json({
      message: "User not found",
    });
    return;
  }

  const comparePassword = await bcrypt.compare(password, user[0].password);
  if (comparePassword) {
    //สร้า่ง token
    const token = jwt.sign({ email: user[0].email, role: "admin" }, secret, {
      expiresIn: "1h",
    });

    res.cookie("token", token, {
      //key ของ cookie ชื่อ token
      httpOnly: true, //คือการกำหนดให้ cookie ไม่สามารถถูกอ่านโดย client side ได้
      secure: true, //ใช้งานได้เฉพาะ https
      sameSite: "none", //frontend port 8888 กับ backend 8000 อยู่คนละ domain ต้องใส่ none
      maxAge: 300000,
    });

    res.json({
      message: "Login success",
    });
  } else {
    res.status(401).json({
      message: "Password not match",
    });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    // const authHeader = req.headers["authorization"]; //Bearer token
    // const token = authHeader && authHeader.split(" ")[1];

    const authHeader = req.cookies.token;
    const token = authHeader;
    const user = jwt.verify(token, secret);
    if (user) {
      const [result] = await conn.query("SELECT * FROM users");
      res.json({
        message: "Get users success",
        users: result[0],
      });
    } else {
      res.status(403).json({
        message: "Unauthorized",
      });
    }
  } catch (err) {
    console.log(err);
    res.status(403).json({
      message: "Unauthorized",
      err,
    });
  }
});
