const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const SECRET = process.env.JWT_SECRET || 'hype_venue_secreto_2026';

// CONFIGURACIÓN DE GMAIL (Agregá estas variables en Railway)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // Ej: tu-correo@gmail.com
        pass: process.env.EMAIL_PASS  // Contraseña de aplicación de Google
    }
});

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --- RUTAS DE AUTENTICACIÓN Y USUARIOS --- (Mantenidas intactas)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.rows[0].id, rol: user.rows[0].rol, evento_id: user.rows[0].evento_id }, SECRET, { expiresIn: '8h' });
    res.json({ token, rol: user.rows[0].rol, evento_id: user.rows[0].evento_id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const verificarToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'Acceso denegado.' });
  jwt.verify(token.split(' ')[1], SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido o vencido' });
    req.usuario = decoded; next();
  });
};

app.post('/api/usuarios', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador') return res.status(403).json({ error: 'Solo el Fundador' });
  try {
    const { email, password, rol, evento_id, nombre, apellido, whatsapp } = req.body;
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO usuarios (email, password, rol, evento_id, nombre, apellido, whatsapp) VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (email) DO UPDATE SET password = EXCLUDED.password, rol = EXCLUDED.rol, evento_id = EXCLUDED.evento_id, nombre = EXCLUDED.nombre, apellido = EXCLUDED.apellido, whatsapp = EXCLUDED.whatsapp`, 
      [email, hash, rol, evento_id || null, nombre, apellido, whatsapp]
    );
    res.json({ mensaje: 'Usuario guardado/actualizado' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/usuarios/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador') return res.status(403).json({ error: 'Solo el Fundador' });
  try { await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]); res.json({ mensaje: 'Borrado' }); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/usuarios', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
  try {
    const usuarios = await pool.query('SELECT u.id, u.email, u.rol, u.nombre, u.apellido, u.whatsapp, e.nombre AS evento_asignado FROM usuarios u LEFT JOIN eventos e ON u.evento_id = e.id ORDER BY u.rol, u.email');
    res.json(usuarios.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reportes/ventas', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
  try {
    const ventas = await pool.query(`SELECT u.id, u.email, u.rol, u.nombre, u.apellido, u.whatsapp, COUNT(t.id) as total_tickets, COALESCE(SUM(t.precio), 0) as total_recaudado FROM usuarios u LEFT JOIN tickets t ON u.id = t.vendedor_id WHERE t.estado = 'Pagado' GROUP BY u.id, u.email, u.rol, u.nombre, u.apellido, u.whatsapp ORDER BY total_tickets DESC`);
    res.json(ventas.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/mis-ventas', verificarToken, async (req, res) => {
  try {
    const misVentas = await pool.query(`SELECT t.codigo_qr, t.precio, t.sector, t.fecha_venta, t.estado, e.nombre AS evento FROM tickets t LEFT JOIN eventos e ON t.evento_id = e.id WHERE t.vendedor_id = $1 ORDER BY COALESCE(t.fecha_venta, '1970-01-01') DESC, t.id DESC`, [req.usuario.id]);
    res.json(misVentas.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/ventas/vendedor/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador') return res.status(403).json({ error: 'Solo Fundador' });
  try { await pool.query('DELETE FROM tickets WHERE vendedor_id = $1', [req.params.id]); res.json({ mensaje: 'Borradas' }); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTAS DE EVENTOS, SECTORES Y PREVENTAS --- (Mantenidas intactas)
app.post('/api/eventos', verificarToken, async (req, res) => {
  try { const nuevoEvento = await pool.query('INSERT INTO eventos (nombre, fecha) VALUES ($1, $2) RETURNING *', [req.body.nombre, req.body.fecha]); res.json(nuevoEvento.rows[0]); } 
  catch (err) { res.status(500).send('Error'); }
});
app.get('/api/eventos', async (req, res) => {
  try { const todosLosEventos = await pool.query('SELECT * FROM eventos WHERE fecha >= NOW() ORDER BY fecha ASC'); res.json(todosLosEventos.rows); } 
  catch (err) { res.status(500).send('Error'); }
});
app.delete('/api/eventos/:id', verificarToken, async (req, res) => {
  try { await pool.query('DELETE FROM eventos WHERE id = $1', [req.params.id]); res.json({ mensaje: 'Borrado' }); } 
  catch (err) { res.status(500).send('Error'); }
});
app.post('/api/sectores', verificarToken, async (req, res) => {
  try { const nuevoSector = await pool.query('INSERT INTO sectores (evento_id, nombre, capacidad) VALUES ($1, $2, $3) RETURNING *', [req.body.evento_id, req.body.nombre, req.body.capacidad]); res.json(nuevoSector.rows[0]); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/sectores/:evento_id', async (req, res) => {
  try { const sectores = await pool.query('SELECT * FROM sectores WHERE evento_id = $1', [req.params.evento_id]); res.json(sectores.rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/preventas', verificarToken, async (req, res) => {
  try { const nueva = await pool.query('INSERT INTO preventas (evento_id, sector_id, nombre, precio, fecha_limite) VALUES ($1, $2, $3, $4, $5) RETURNING *', [req.body.evento_id, req.body.sector_id, req.body.nombre, req.body.precio, req.body.fecha_limite || null]); res.json(nueva.rows[0]); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/preventas/:evento_id', verificarToken, async (req, res) => {
  try { const preventas = await pool.query(`SELECT p.*, s.nombre AS sector_nombre FROM preventas p JOIN sectores s ON p.sector_id = s.id WHERE p.evento_id = $1`, [req.params.evento_id]); res.json(preventas.rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/preventas/:id', verificarToken, async (req, res) => {
  try { const actualizada = await pool.query('UPDATE preventas SET nombre = $1, precio = $2, fecha_limite = $3 WHERE id = $4 RETURNING *', [req.body.nombre, req.body.precio, req.body.fecha_limite || null, req.params.id]); res.json(actualizada.rows[0]); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/preventas/:id', verificarToken, async (req, res) => {
  try { await pool.query('DELETE FROM preventas WHERE id = $1', [req.params.id]); res.json({ mensaje: 'Borrada' }); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTAS DE TICKETS (VENTA) ---
app.post('/api/tickets', verificarToken, async (req, res) => {
  try {
    let { evento_id, sector_id, cantidad } = req.body;
    const vendedor_id = req.usuario.id; 
    cantidad = parseInt(cantidad) || 1;

    if (req.usuario.rol === 'Vendedor') {
      if (!req.usuario.evento_id) return res.status(403).json({ error: 'Vendedor sin evento.' });
      evento_id = req.usuario.evento_id;
    }

    const sectorData = await pool.query('SELECT * FROM sectores WHERE id = $1', [sector_id]);
    if (sectorData.rows.length === 0) return res.status(400).json({ error: 'Sector no encontrado' });
    const sector = sectorData.rows[0];

    const preventaQuery = await pool.query('SELECT * FROM preventas WHERE evento_id = $1 AND sector_id = $2 AND (fecha_limite IS NULL OR fecha_limite >= NOW()) ORDER BY fecha_limite ASC LIMIT 1', [evento_id, sector_id]);
    if (preventaQuery.rows.length === 0) return res.status(400).json({ error: 'No hay preventas activas' });
    const preventaActiva = preventaQuery.rows[0];

    const linksGenerados = [];

    // Ahora los tickets se guardan con estado "Pendiente" automáticamente
    for(let i = 0; i < cantidad; i++) {
        const codigo_qr = crypto.randomUUID(); 
        await pool.query(
          'INSERT INTO tickets (evento_id, vendedor_id, codigo_qr, precio, sector, estado, fecha_venta) VALUES ($1, $2, $3, $4, $5, $6, NOW())',
          [evento_id, vendedor_id, codigo_qr, preventaActiva.precio, sector.nombre, 'Pendiente']
        );
        linksGenerados.push(`https://hypevenue.up.railway.app/comprar/${codigo_qr}`);
    }

    res.json({ links: linksGenerados, precio: preventaActiva.precio, tanda: preventaActiva.nombre, cantidad });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- RUTA NUEVA PARA INICIAR PAGO EN NAVE ---
app.post('/api/iniciar-pago', async (req, res) => {
  try {
      const { codigo, email } = req.body;
      
      // Actualizamos el ticket con el correo que ingresó el usuario
      const ticketQ = await pool.query('UPDATE tickets SET email_comprador = $1 WHERE codigo_qr = $2 AND estado = $3 RETURNING *', [email, codigo, 'Pendiente']);
      
      if (ticketQ.rows.length === 0) return res.status(400).json({ error: 'Ticket no válido o ya pagado.' });
      const ticket = ticketQ.rows[0];

      // --- NAVE API: AQUÍ VA LA CONEXIÓN A NAVE PARA GENERAR EL LINK DE PAGO ---
      // Ejemplo de código cuando tengas las credenciales:
      /*
      const response = await axios.post('https://api.nave.com/v1/checkout', {
          monto: ticket.precio,
          referencia_externa: ticket.codigo_qr,
          email: email
      }, { headers: { 'Authorization': `Bearer TU_CLIENT_SECRET_DE_NAVE` }});
      const urlPago = response.data.url;
      */

      // Simulador temporal hasta que configures Nave (Borrar esto cuando tengas la API)
      const urlPago = `https://hypevenue.up.railway.app/simulador-pago-exitoso/${ticket.codigo_qr}`; 

      res.json({ url: urlPago });
  } catch (err) {
      res.status(500).json({ error: 'Error al procesar el pago' });
  }
});

// --- RUTA NUEVA DEL WEBHOOK DE NAVE ---
app.post('/api/webhooks/nave', async (req, res) => {
    try {
        // NAVE API: Capturar la respuesta real de Nave. 
        // Suponiendo que Nave manda { status: 'approved', reference: 'codigo_qr_del_ticket' }
        const { status, reference } = req.body; 

        if (status === 'approved' || status === 'paid') {
            const result = await pool.query('UPDATE tickets SET estado = $1 WHERE codigo_qr = $2 AND estado = $3 RETURNING *', ['Pagado', reference, 'Pendiente']);
            
            if (result.rows.length > 0) {
                const ticketPagado = result.rows[0];
                const eventoQuery = await pool.query('SELECT nombre FROM eventos WHERE id = $1', [ticketPagado.evento_id]);
                const eventoNombre = eventoQuery.rows[0] ? eventoQuery.rows[0].nombre : 'Evento Hype';

                // Mandar el correo con Nodemailer
                const linkEntrada = `https://hypevenue.up.railway.app/comprar/${ticketPagado.codigo_qr}`;
                const mailOptions = {
                    from: '"Hype Venue" <hypevenue@gmail.com>', // Cambiá por tu correo
                    to: ticketPagado.email_comprador,
                    subject: `Tu entrada para ${eventoNombre} está lista`,
                    html: `<div style="font-family: Arial, sans-serif; text-align: center; padding: 30px; background: #111; color: #fff; border-radius: 10px;">
                            <h1 style="color: #00ffcc;">¡Pago Exitoso!</h1>
                            <p>Ya tenés tu lugar asegurado en el sector <strong>${ticketPagado.sector}</strong>.</p>
                            <a href="${linkEntrada}" style="background: #00ffcc; color: #000; padding: 15px 25px; text-decoration: none; font-weight: bold; border-radius: 5px; display: inline-block; margin-top: 20px;">VER MI ENTRADA (CÓDIGO QR)</a>
                           </div>`
                };
                transporter.sendMail(mailOptions).catch(console.error);
            }
        }
        res.sendStatus(200); // Responderle a Nave que recibimos bien la info
    } catch (err) {
        res.sendStatus(500);
    }
});

// --- RUTA TEMPORAL PARA SIMULAR QUE NAVE PAGÓ (Borrar luego) ---
app.get('/simulador-pago-exitoso/:codigo', async (req, res) => {
    // Simulamos que el webhook de Nave llamó a nuestro servidor
    await axios.post('http://localhost:' + PORT + '/api/webhooks/nave', { status: 'approved', reference: req.params.codigo });
    // Redirigimos al cliente a su entrada
    res.redirect(`/comprar/${req.params.codigo}`);
});


// --- VISTA FINAL DEL COMPRADOR ---
app.get('/comprar/:codigo', async (req, res) => {
  try {
    const ticketQuery = await pool.query('SELECT * FROM tickets WHERE codigo_qr = $1', [req.params.codigo]);
    if (ticketQuery.rows.length === 0) return res.status(404).send('<h1>Ticket no encontrado o inválido</h1>');

    const ticket = ticketQuery.rows[0];
    const eventoQuery = await pool.query('SELECT * FROM eventos WHERE id = $1', [ticket.evento_id]);
    const evento = eventoQuery.rows[0] ? eventoQuery.rows[0].nombre : 'Evento Hype';

    // SI ESTÁ PENDIENTE: Le pedimos el correo para ir a Nave
    if (ticket.estado === 'Pendiente') {
        return res.send(`
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Completar Pago - Hype Venue</title>
                <style>
                    body { font-family: 'Arial', sans-serif; background: #000; color: #fff; text-align: center; padding: 40px; }
                    .card { background: #111; padding: 30px; border-radius: 12px; max-width: 400px; margin: auto; border: 1px solid #333; }
                    input, button { width: 100%; padding: 12px; margin-top: 15px; box-sizing: border-box; border-radius: 6px; font-size: 16px; }
                    input { background: #222; color: #fff; border: 1px solid #444; }
                    button { background: #00ffcc; color: #000; border: none; font-weight: bold; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h2 style="color: #00ffcc; margin-top:0;">HYPE VENUE</h2>
                    <h3>${evento} - Sector: ${ticket.sector}</h3>
                    <p>Total a pagar: <strong>$${ticket.precio}</strong></p>
                    <p style="font-size: 14px; color: #aaa;">Ingresá tu correo electrónico. A este mail te va a llegar la entrada con el código QR una vez que finalices el pago.</p>
                    
                    <form id="formPago">
                        <input type="email" id="emailCompra" placeholder="tu-correo@ejemplo.com" required>
                        <button type="submit" id="btnPagar">Ir a Pagar</button>
                    </form>
                </div>
                <script>
                    document.getElementById('formPago').addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const btn = document.getElementById('btnPagar');
                        btn.innerText = 'Redirigiendo...';
                        btn.disabled = true;

                        const email = document.getElementById('emailCompra').value;
                        const response = await fetch('/api/iniciar-pago', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ codigo: '${ticket.codigo_qr}', email: email })
                        });
                        const data = await response.json();
                        if(data.url) window.location.href = data.url; // Redirige a Nave
                        else alert('Error al iniciar pago');
                    });
                </script>
            </body>
            </html>
        `);
    }

    // SI ESTÁ PAGADO: Le mostramos la entrada final
    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Tu Entrada - Hype Venue</title>
          <style>
              body { font-family: Arial; background: #000; color: #fff; text-align: center; padding: 40px; }
              .card { background: #111; padding: 30px; border-radius: 12px; max-width: 400px; margin: auto; border: 2px solid #00ffcc; box-shadow: 0 0 20px rgba(0, 255, 204, 0.2); }
              h1 { color: #00ffcc; margin-bottom: 10px; letter-spacing: 3px;}
              .precio { font-size: 24px; color: #00ffcc; font-weight: bold; margin: 20px 0; }
              .info { margin: 10px 0; color: #ccc; }
              .badge-pagado { background: #00ffcc; color: #000; display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; margin-bottom: 15px; }
          </style>
      </head>
      <body>
          <div class="card">
              <div class="badge-pagado">✔ PAGADO</div>
              <h1>HYPE VENUE</h1>
              <h3>${evento}</h3>
              <p class="info">Sector: <strong>${ticket.sector}</strong></p>
              <div class="precio">$${ticket.precio}</div>
              <p style="font-size: 12px; color: #888;">Código único: ${ticket.codigo_qr}</p>
              <p style="margin-top: 20px; font-size: 14px; color: #ffaa00;">Presentá esta pantalla en puerta.</p>
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
