import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cors from "cors";
import { pool } from "./db.js";

const app = express();
const PORT = 5000;
const JWT_SECRET = "your_jwt_secret";

app.use(bodyParser.json());
app.use(cors());

// Middleware para verificar token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Token requerido" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token inválido" });
    req.user = user;
    next();
  });
};

// Home
app.get("/", (req, res) => {
  res.send("Bienvenido a la API con PostgreSQL + JWT");
});

// Sign in
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(404).json({ message: "Usuario no encontrado" });

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(String(password), String(user.password));

    if (!isPasswordValid) return res.status(400).json({ message: "Credenciales inválidas" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// GET: /users
app.get("/users", verifyToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, email FROM users");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Error al obtener usuarios" });
  }
});

// GET: /users/:id
app.get("/users/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query("SELECT id, email FROM users WHERE id = $1", [id]);
    if (result.rows.length === 0) return res.status(404).json({ message: "Usuario no encontrado" });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: "Error al obtener usuario" });
  }
});

// POST: /users
app.post("/users", verifyToken, async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email, hashed]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: "Error al crear usuario" });
  }
});

// PUT: /users/:id
app.put("/users/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    await pool.query("UPDATE users SET email = $1, password = $2 WHERE id = $3", [email, hashed, id]);
    res.json({ message: "Usuario actualizado" });
  } catch (err) {
    res.status(500).json({ message: "Error al actualizar usuario" });
  }
});

// DELETE: /users/:id
app.delete("/users/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM users WHERE id = $1", [id]);
    res.json({ message: "Usuario eliminado" });
  } catch (err) {
    res.status(500).json({ message: "Error al eliminar usuario" });
  }
});

app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
