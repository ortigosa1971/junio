const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const db = new sqlite3.Database('./db/usuarios.db', (err) => {
  if (err) console.error("❌ Error al conectar con la base de datos:", err.message);
  else console.log("✅ Conectado a la base de datos usuarios.db");
});

// Configuración de sesión


app.set('trust proxy', 1);

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: './db' }),
  secret: 'tu_secreto',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 3600000,
    secure: true,
    sameSite: 'none'
  }
}));


// Middleware para parsear formularios
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Página principal protegida
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

// Página de inicio protegida
app.get('/inicio.html', (req, res) => {
  if (!req.session.user) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

// Verificación de sesión activa
app.get('/verificar-sesion', (req, res) => {
  if (!req.session.user) {
    console.log("🔒 [verificar-sesion] No hay sesión activa");
    return res.sendStatus(401);
  }

  db.get('SELECT session_id FROM users WHERE username = ?', [req.session.user.username], (err, row) => {
    if (err) {
      console.error("⚠️ [verificar-sesion] Error al verificar sesión:", err.message);
      return req.session.destroy(() => res.sendStatus(500));
    }

    if (!row || row.session_id !== req.sessionID) {
      console.log("⛔ Sesión no coincide o usuario no encontrado. Cerrando sesión.");
      req.session.destroy(() => res.sendStatus(401));
    } else {
      res.sendStatus(200);
    }
  });
});

// Manejo de login
app.post('/login', (req, res) => {
  const { usuario } = req.body;

  if (!usuario || usuario.trim() === "") {
    console.log("⚠️ [login] Usuario vacío");
    return res.redirect('/login.html?error=1');
  }

  db.get('SELECT * FROM users WHERE username = ?', [usuario], (err, row) => {
    if (err) {
      console.error("⚠️ [login] Error al buscar usuario:", err.message);
      return res.redirect('/login.html?error=1');
    }

    if (!row) {
      console.log("❌ [login] Usuario no encontrado:", usuario);
      return res.redirect('/login.html?error=1');
    }

    console.log("🔓 [login] Usuario autenticado:", usuario);

    // Cerrar cualquier sesión anterior
    db.run('UPDATE users SET session_id = NULL WHERE username = ?', [usuario], (err) => {
      if (err) {
        console.error("❌ Error limpiando session_id previo:", err.message);
        return res.redirect('/login.html?error=1');
      }

      // Crear nueva sesión
      req.session.user = { username: row.username };

      // Guardar nuevo session_id en la base de datos
      db.run('UPDATE users SET session_id = ? WHERE username = ?', [req.sessionID, row.username], (err) => {
        if (err) {
          console.error("❌ Error actualizando session_id nuevo:", err.message);
          return res.redirect('/login.html?error=1');
        }

        console.log(`✅ [login] session_id actualizado: ${req.sessionID}`);
        res.redirect('/inicio.html');
      });
    });
  });
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor escuchando en puerto ${PORT}`));



// Nuevo endpoint para datos meteorológicos
app.get('/clima', (req, res) => {
    const weatherData = {
        temperatura: 25,
        humedad: 60,
        viento: 12,
        presion: 1015,
        lluvia: 0
    };
    res.json(weatherData);
});

