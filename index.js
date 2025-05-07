// 📁 index.js (com autenticação JWT, registro de usuários e logs)

import fs from 'fs';
import path from 'path';
import express from "express";
import multer from "multer";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import archiver from "archiver";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const app = express();
const PORT = 5000;

const UPLOADS_DIR = path.resolve("./uploads");
const LINKS_FILE = path.resolve("./file-links.json");
const LOGS_FILE = path.resolve("./logs.json");
const USERS_FILE = path.resolve("./users.json");

const JWT_SECRET = "divtransfer_secret"; // troque para um valor seguro em produção
const ADMIN_EMAIL = "swot1178@gmail.com";

// Cria pastas/arquivos se não existirem
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(LINKS_FILE)) fs.writeFileSync(LINKS_FILE, JSON.stringify({}));
if (!fs.existsSync(LOGS_FILE)) fs.writeFileSync(LOGS_FILE, JSON.stringify([]));
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(UPLOADS_DIR));

// Middleware: autenticação JWT
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token ausente" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// Middleware: apenas admin
function adminOnly(req, res, next) {
  if (req.user?.email === ADMIN_EMAIL) {
    return next();
  }
  return res.status(403).json({ error: "Acesso apenas para admin" });
}

// POST /register
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "E-mail e senha são obrigatórios" });

  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  if (users.find(u => u.email === email))
    return res.status(409).json({ error: "E-mail já cadastrado" });

  const passwordHash = await bcrypt.hash(password, 10);
  const role = email === ADMIN_EMAIL ? "admin" : "user";

  users.push({ email, passwordHash, role });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

  res.status(201).json({ message: "Conta criada com sucesso" });
});

// POST /login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: "Credenciais inválidas" });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: "Credenciais inválidas" });

  const token = jwt.sign({ email: user.email, role: user.role }, JWT_SECRET, {
    expiresIn: "2h",
  });

  res.status(200).json({ token });
});

// Multer: salvar arquivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  },
});
const upload = multer({ storage });

// POST /upload
app.post("/upload", upload.array("file"), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: "Nenhum arquivo enviado" });
  }

  const email = req.body.email;
  const filenames = req.files.map((file) => file.filename);
  const uuid = uuidv4();

  const linksData = JSON.parse(fs.readFileSync(LINKS_FILE));
  linksData[uuid] = filenames;
  fs.writeFileSync(LINKS_FILE, JSON.stringify(linksData, null, 2));

  const logEntries = JSON.parse(fs.readFileSync(LOGS_FILE));
  const newEntry = {
    email,
    timestamp: new Date().toISOString(),
    files: filenames,
    ip: req.ip
  };
  logEntries.push(newEntry);
  fs.writeFileSync(LOGS_FILE, JSON.stringify(logEntries, null, 2));

  return res.status(200).json({ filenames });
});

// GET /download/:uuid
app.get("/download/:uuid", (req, res) => {
  const { uuid } = req.params;

  const linksData = JSON.parse(fs.readFileSync(LINKS_FILE));
  const files = linksData[uuid];

  if (!files || files.length === 0) {
    return res.status(404).json({ error: "Link não encontrado" });
  }

  res.setHeader("Content-Disposition", `attachment; filename=arquivos.zip`);
  res.setHeader("Content-Type", "application/zip");

  const archive = archiver("zip", { zlib: { level: 9 } });
  archive.pipe(res);

  files.forEach((filename) => {
    const filepath = path.join(UPLOADS_DIR, filename);
    archive.file(filepath, { name: filename });
  });

  archive.finalize();
});

// GET /logs (protegido por autenticação e adminOnly)
app.get("/logs", authMiddleware, adminOnly, (req, res) => {
  try {
    const logEntries = JSON.parse(fs.readFileSync(LOGS_FILE));
    const linksData = JSON.parse(fs.readFileSync(LINKS_FILE));
    const formattedLogs = [];

    for (const entry of logEntries) {
      for (const file of entry.files) {
        const filePath = path.join(UPLOADS_DIR, file);
        const fileSize = fs.existsSync(filePath)
          ? fs.statSync(filePath).size
          : 0;

        const downloadUUID = Object.keys(linksData).find((uuid) =>
          linksData[uuid].includes(file)
        );

        const downloadLink = downloadUUID
          ? `http://localhost:5000/download/${downloadUUID}`
          : "Link não encontrado";

        formattedLogs.push({
          email: entry.email,
          fileName: file,
          fileSize,
          downloadLink,
          ipAddress: entry.ip,
          timestamp: entry.timestamp,
        });
      }
    }

    return res.status(200).json(formattedLogs);
  } catch (err) {
    return res.status(500).json({ error: "Erro ao processar logs" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend rodando: http://localhost:${PORT}`);
});
