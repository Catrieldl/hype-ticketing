const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const SECRET = process.env.JWT_SECRET || 'hype_venue_secreto_2026';

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.rows[0].id, rol: user.rows[0].rol }, SECRET, { expiresIn: '8h' });
    res.json({ token, rol: user.rows[0].rol });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const verificarToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'Acceso denegado.' });
  jwt.verify(token.split(' ')[1], SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido o vencido' });
    req.usuario = decoded; 
    next();
  });
};

// NUEVO: Crear usuarios (Solo Fundador)
app.post('/api/usuarios', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador') return res.status(403).json({ error: 'Solo el Fundador puede hacer esto' });
  try {
    const { email, password, rol } = req.body;
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO usuarios (email, password, rol) VALUES ($1, $2, $3)', [email, hash, rol]);
    res.json({ mensaje: 'Usuario creado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/eventos', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') {
     return res.status(403).json({ error: 'Sin permisos' });
  }
  try {
    const { nombre, fecha } = req.body;
    const nuevoEvento = await pool.query('INSERT INTO eventos (nombre, fecha) VALUES ($1, $2) RETURNING *', [nombre, fecha]);
    res.json(nuevoEvento.rows[0]);
  } catch (err) {
    res.status(500).send('Error');
  }
});

app.get('/api/eventos', async (req, res) => {
  try {
    const todosLosEventos = await pool.query('SELECT * FROM eventos ORDER BY fecha ASC');
    res.json(todosLosEventos.rows);
  } catch (err) {
    res.status(500).send('Error');
  }
});

app.delete('/api/eventos/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador') {
     return res.status(403).json({ error: 'Solo Fundador' });
  }
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM eventos WHERE id = $1', [id]);
    res.json({ mensaje: 'Borrado' });
  } catch (err) {
    res.status(500).send('Error');
  }
});
// Ruta para generar link de venta
app.post('/api/tickets', verificarToken, async (req, res) => {
  try {
    const { evento_id, precio } = req.body;
    const vendedor_id = req.usuario.id; // El sistema sabe qué vendedor está logueado
    const codigo_qr = crypto.randomUUID(); // Genera un código alfanumérico único

    await pool.query(
      'INSERT INTO tickets (evento_id, vendedor_id, codigo_qr, precio) VALUES ($1, $2, $3, $4)',
      [evento_id, vendedor_id, codigo_qr, precio]
    );

    // Este es el link que el RRPP le va a mandar al cliente por WhatsApp
    const linkVenta = `https://hype-ticketing-production.up.railway.app/comprar/${codigo_qr}`;
    res.json({ link: linkVenta });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Puerto ${PORT}`);
});
