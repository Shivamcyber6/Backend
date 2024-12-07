const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(cors());

// MySQL Connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "user_auth_db",
});

db.connect((err) => {

  console.log("Connected to MySQL");
});

// Register API
app.post("/api/signup", async (req, res) => {
  const { firstName, lastName, email, countryCode, phoneNumber, password, dob, gender } = req.body;

  // Validation
  if (!firstName || !lastName || !email || !countryCode || !phoneNumber || !password || !dob || !gender) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO users (first_name, last_name, email, country_code, phone_number, password, date_of_birth, gender) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(
      sql,
      [firstName, lastName, email, countryCode, phoneNumber, hashedPassword, dob, gender],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "Email or Phone Number already exists" });
          }
          return res.status(500).json({ message: "Database error" });
        }
        res.status(201).json({ message: "User signed up successfully" });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Login API
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).json({ message: "Database error" });

    if (results.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = results[0];
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Logged in successfully", token });
  });
});

app.listen(5003, () => {
  console.log("Server is running on port 5003");
});
