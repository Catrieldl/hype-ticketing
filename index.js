const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const SECRET = process.env.JWT_SECRET || 'hype_venue_secreto_2026';

// Servir la carpeta actual como pública y forzar el index.html en la raíz
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

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
    const todosLosEventos = await pool.query('SELECT * FROM eventos WHERE fecha >= NOW() ORDER BY fecha ASC');
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

app.post('/api/sectores', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') {
     return res.status(403).json({ error: 'Sin permisos' });
  }
  try {
    const { evento_id, nombre, capacidad } = req.body;
    const nuevoSector = await pool.query(
      'INSERT INTO sectores (evento_id, nombre, capacidad) VALUES ($1, $2, $3) RETURNING *',
      [evento_id, nombre, capacidad]
    );
    res.json(nuevoSector.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sectores/:evento_id', async (req, res) => {
  try {
    const { evento_id } = req.params;
    const sectores = await pool.query('SELECT * FROM sectores WHERE evento_id = $1', [evento_id]);
    res.json(sectores.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/preventas', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') {
     return res.status(403).json({ error: 'Sin permisos' });
  }
  try {
    const { evento_id, sector_id, nombre, precio, fecha_limite } = req.body;
    const nueva = await pool.query(
      'INSERT INTO preventas (evento_id, sector_id, nombre, precio, fecha_limite) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [evento_id, sector_id, nombre, precio, fecha_limite || null]
    );
    res.json(nueva.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/tickets', verificarToken, async (req, res) => {
  try {
    const { evento_id, sector_id } = req.body;
    const vendedor_id = req.usuario.id; 
    const codigo_qr = crypto.randomUUID(); 

    const sectorData = await pool.query('SELECT * FROM sectores WHERE id = $1', [sector_id]);
    if (sectorData.rows.length === 0) return res.status(400).json({ error: 'Sector no encontrado' });
    const sector = sectorData.rows[0];

    const ticketsVendidosQuery = await pool.query(
      'SELECT COUNT(*) FROM tickets WHERE evento_id = $1 AND sector = $2',
      [evento_id, sector.nombre]
    );
    const totalVendidos = parseInt(ticketsVendidosQuery.rows[0].count);

    if (totalVendidos >= sector.capacidad) {
      return res.status(400).json({ error: `El sector ${sector.nombre} ha alcanzado su capacidad máxima (${sector.capacidad} entradas).` });
    }

    const preventaQuery = await pool.query(
      'SELECT * FROM preventas WHERE evento_id = $1 AND sector_id = $2 AND (fecha_limite IS NULL OR fecha_limite >= NOW()) ORDER BY fecha_limite ASC LIMIT 1',
      [evento_id, sector_id]
    );

    if (preventaQuery.rows.length === 0) {
      return res.status(400).json({ error: 'No hay preventas activas configuradas para este sector' });
    }

    const preventaActiva = preventaQuery.rows[0];

    await pool.query(
      'INSERT INTO tickets (evento_id, vendedor_id, codigo_qr, precio, sector) VALUES ($1, $2, $3, $4, $5)',
      [evento_id, vendedor_id, codigo_qr, preventaActiva.precio, sector.nombre]
    );

    const linkVenta = `https://hypevenue.up.railway.app/comprar/${codigo_qr}`;
    res.json({ link: linkVenta, precio: preventaActiva.precio, tanda: preventaActiva.nombre });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Puerto ${PORT}`);
});
