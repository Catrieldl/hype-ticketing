const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Llave secreta para los tokens
const SECRET = process.env.JWT_SECRET || 'hype_venue_secreto_2026';

// 1. Ruta temporal para crear tu usuario Dueño (luego la borramos por seguridad)
app.post('/api/registrar', async (req, res) => {
  try {
    const { email, password, rol } = req.body;
    const hash = await bcrypt.hash(password, 10); // Encripta la contraseña
    await pool.query(
      'INSERT INTO usuarios (email, password, rol) VALUES ($1, $2, $3)',
      [email, hash, rol]
    );
    res.json({ mensaje: 'Usuario creado exitosamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Ruta de Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    
    if (user.rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

    // Genera el pase de acceso con el rol del usuario
    const token = jwt.sign({ id: user.rows[0].id, rol: user.rows[0].rol }, SECRET, { expiresIn: '8h' });
    res.json({ token, rol: user.rows[0].rol });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Sistema de control de seguridad (Middleware)
const verificarToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'Acceso denegado. Faltan credenciales.' });
  
  jwt.verify(token.split(' ')[1], SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido o vencido' });
    req.usuario = decoded; // Guarda los datos del usuario (id y rol)
    next();
  });
};

// 4. Rutas protegidas de Eventos
app.post('/api/eventos', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Dueño' && req.usuario.rol !== 'Admin') {
     return res.status(403).json({ error: 'No tienes permiso para crear eventos' });
  }
  try {
    const { nombre, fecha } = req.body;
    const nuevoEvento = await pool.query(
      'INSERT INTO eventos (nombre, fecha) VALUES ($1, $2) RETURNING *',
      [nombre, fecha]
    );
    res.json(nuevoEvento.rows[0]);
  } catch (err) {
    res.status(500).send('Error en el servidor');
  }
});

app.get('/api/eventos', async (req, res) => {
  try {
    const todosLosEventos = await pool.query('SELECT * FROM eventos ORDER BY fecha ASC');
    res.json(todosLosEventos.rows);
  } catch (err) {
    res.status(500).send('Error en el servidor');
  }
});

app.delete('/api/eventos/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Dueño') {
     return res.status(403).json({ error: 'Solo el Dueño puede borrar eventos' });
  }
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM eventos WHERE id = $1', [id]);
    res.json({ mensaje: 'Evento eliminado' });
  } catch (err) {
    res.status(500).send('Error en el servidor');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
