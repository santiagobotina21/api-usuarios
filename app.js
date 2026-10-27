const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const app = express();
app.use(cors());
app.use(express.json());

let usuarios = [];

const hashPassword = (password) => {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
};

const isPasswordValid = (password, storedPassword) => {
  const [salt, storedHash] = storedPassword.split(":");
  if (!salt || !storedHash) {
    return false;
  }

  const hash = crypto.scryptSync(password, salt, 64);
  const expectedHash = Buffer.from(storedHash, "hex");
  return (
    hash.length === expectedHash.length &&
    crypto.timingSafeEqual(hash, expectedHash)
  );
};

app.get("/", (req, res) => {
  res.send("✅ API de Registro e Inicio de Sesión funcionando");
});

app.post("/api/register", (req, res) => {
  const username =
    typeof req.body?.username === "string" ? req.body.username.trim() : "";
  const password =
    typeof req.body?.password === "string" ? req.body.password : "";

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "El usuario y la contraseña son obligatorios" });
  }

  if (username.length < 3 || username.length > 30) {
    return res
      .status(400)
      .json({ message: "El usuario debe tener entre 3 y 30 caracteres" });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ message: "La contraseña debe tener al menos 6 caracteres" });
  }

  const usernameKey = username.toLowerCase();
  const existe = usuarios.find((u) => u.usernameKey === usernameKey);
  if (existe) {
    return res.status(409).json({ message: "El usuario ya está registrado" });
  }

  usuarios.push({
    username,
    usernameKey,
    passwordHash: hashPassword(password),
  });

  return res
    .status(201)
    .json({ message: "✅ Usuario registrado correctamente" });
});

app.post("/api/login", (req, res) => {
  const username =
    typeof req.body?.username === "string" ? req.body.username.trim() : "";
  const password =
    typeof req.body?.password === "string" ? req.body.password : "";
  const usuario = usuarios.find(
    (u) =>
      u.usernameKey === username.toLowerCase() &&
      isPasswordValid(password, u.passwordHash),
  );
  if (usuario) {
    res.json({ message: "✅ Autenticación satisfactoria" });
  } else {
    res.status(401).json({ message: "Usuario o contraseña incorrectos" });
  }
});

app.get("/api/usuarios", (req, res) => {
  res.json(usuarios.map(({ username }) => ({ username })));
});

app.listen(4000, () => {
  console.log("Servidor corriendo en http://localhost:4000");
});
