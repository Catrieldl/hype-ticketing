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

    const token = jwt.sign({ 
      id: user.rows[0].id, 
      rol: user.rows[0].rol,
      evento_id: user.rows[0].evento_id 
    }, SECRET, { expiresIn: '8h' });
    
    res.json({ token, rol: user.rows[0].rol, evento_id: user.rows[0].evento_id });
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
  if (req.usuario.rol !== 'Fundador') return res.status(403).json({ error: 'Solo el Fundador' });
  try {
    const { email, password, rol, evento_id } = req.body;
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO usuarios (email, password, rol, evento_id) 
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (email) 
       DO UPDATE SET password = EXCLUDED.password, rol = EXCLUDED.rol, evento_id = EXCLUDED.evento_id`, 
      [email, hash, rol, evento_id || null]
    );
    res.json({ mensaje: 'Usuario guardado/actualizado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/eventos', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
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
  if (req.usuario.rol !== 'Fundador') return res.status(403).json({ error: 'Solo Fundador' });
  try {
    await pool.query('DELETE FROM eventos WHERE id = $1', [req.params.id]);
    res.json({ mensaje: 'Borrado' });
  } catch (err) {
    res.status(500).send('Error');
  }
});

app.post('/api/sectores', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
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
    const sectores = await pool.query('SELECT * FROM sectores WHERE evento_id = $1', [req.params.evento_id]);
    res.json(sectores.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/preventas', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
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

app.get('/api/preventas/:evento_id', verificarToken, async (req, res) => {
  try {
    const preventas = await pool.query(`
      SELECT p.*, s.nombre AS sector_nombre FROM preventas p 
      JOIN sectores s ON p.sector_id = s.id WHERE p.evento_id = $1
    `, [req.params.evento_id]);
    res.json(preventas.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/preventas/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
  try {
    const { nombre, precio, fecha_limite } = req.body;
    const actualizada = await pool.query(
      'UPDATE preventas SET nombre = $1, precio = $2, fecha_limite = $3 WHERE id = $4 RETURNING *',
      [nombre, precio, fecha_limite || null, req.params.id]
    );
    res.json(actualizada.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/preventas/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
  try {
    await pool.query('DELETE FROM preventas WHERE id = $1', [req.params.id]);
    res.json({ mensaje: 'Preventa borrada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// MODIFICADO: Generación múltiple
app.post('/api/tickets', verificarToken, async (req, res) => {
  try {
    let { evento_id, sector_id, cantidad } = req.body;
    const vendedor_id = req.usuario.id; 
    cantidad = parseInt(cantidad) || 1; // Default a 1 si no manda nada

    if (req.usuario.rol === 'Vendedor') {
      if (!req.usuario.evento_id) return res.status(403).json({ error: 'Vendedor sin evento asignado.' });
      evento_id = req.usuario.evento_id;
    }

    const sectorData = await pool.query('SELECT * FROM sectores WHERE id = $1', [sector_id]);
    if (sectorData.rows.length === 0) return res.status(400).json({ error: 'Sector no encontrado' });
    const sector = sectorData.rows[0];

    const ticketsVendidos = await pool.query('SELECT COUNT(*) FROM tickets WHERE evento_id = $1 AND sector = $2', [evento_id, sector.nombre]);
    const totalVendidos = parseInt(ticketsVendidos.rows[0].count);

    if (totalVendidos + cantidad > sector.capacidad) {
      return res.status(400).json({ error: `Capacidad excedida. Solo quedan ${sector.capacidad - totalVendidos} lugares.` });
    }

    const preventaQuery = await pool.query(
      'SELECT * FROM preventas WHERE evento_id = $1 AND sector_id = $2 AND (fecha_limite IS NULL OR fecha_limite >= NOW()) ORDER BY fecha_limite ASC LIMIT 1',
      [evento_id, sector_id]
    );

    if (preventaQuery.rows.length === 0) return res.status(400).json({ error: 'No hay preventas activas' });
    const preventaActiva = preventaQuery.rows[0];

    const linksGenerados = [];

    // Bucle para insertar "n" tickets
    for(let i = 0; i < cantidad; i++) {
        const codigo_qr = crypto.randomUUID(); 
        await pool.query(
          'INSERT INTO tickets (evento_id, vendedor_id, codigo_qr, precio, sector) VALUES ($1, $2, $3, $4, $5)',
          [evento_id, vendedor_id, codigo_qr, preventaActiva.precio, sector.nombre]
        );
        linksGenerados.push(`https://hypevenue.up.railway.app/comprar/${codigo_qr}`);
    }

    res.json({ links: linksGenerados, precio: preventaActiva.precio, tanda: preventaActiva.nombre, cantidad });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/comprar/:codigo', async (req, res) => {
  try {
    const ticketQuery = await pool.query('SELECT * FROM tickets WHERE codigo_qr = $1', [req.params.codigo]);
    if (ticketQuery.rows.length === 0) return res.status(404).send('<h1>Ticket no encontrado o inválido</h1>');

    const ticket = ticketQuery.rows[0];
    const eventoQuery = await pool.query('SELECT * FROM eventos WHERE id = $1', [ticket.evento_id]);
    const evento = eventoQuery.rows[0] ? eventoQuery.rows[0].nombre : 'Evento Hype';

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Tu Entrada - Hype Venue</title>
          <style>
              body { font-family: Arial; background: #111; color: #fff; text-align: center; padding: 40px; }
              .card { background: #222; padding: 30px; border-radius: 12px; max-width: 400px; margin: auto; border: 2px solid #444; }
              h1 { color: #00ffcc; margin-bottom: 10px; }
              .precio { font-size: 24px; color: #00ffcc; font-weight: bold; margin: 20px 0; }
              .info { margin: 10px 0; color: #ccc; }
          </style>
      </head>
      <body>
          <div class="card">
              <h1>HYPE VENUE</h1>
              <h3>${evento}</h3>
              <p class="info">Sector: <strong>${ticket.sector}</strong></p>
              <div class="precio">$${ticket.precio}</div>
              <p style="font-size: 12px; color: #888;">Código único: ${ticket.codigo_qr}</p>
              <p style="margin-top: 20px; font-size: 14px; color: #ffaa00;">Presentá este código en puerta.</p>
          </div>
      </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send('Error en el servidor');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Puerto ${PORT}`));
