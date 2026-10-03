const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const axios = require('axios');

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

// --- RUTAS DE AUTENTICACIÓN Y USUARIOS ---
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
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
  try {
    if (req.usuario.rol === 'Admin') {
      const target = await pool.query('SELECT rol FROM usuarios WHERE id = $1', [req.params.id]);
      if (target.rows.length > 0 && target.rows[0].rol === 'Fundador') {
        return res.status(403).json({ error: 'Un Admin no puede borrar al Fundador.' });
      }
    }
    await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]); 
    res.json({ mensaje: 'Borrado' }); 
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/usuarios/:id/evento', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
  try {
    const ev_id = req.body.evento_id ? req.body.evento_id : null;
    await pool.query('UPDATE usuarios SET evento_id = $1 WHERE id = $2', [ev_id, req.params.id]);
    res.json({ mensaje: 'Evento reasignado correctamente' });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    const ventas = await pool.query(`SELECT u.id, u.email, u.rol, u.nombre, u.apellido, u.whatsapp, COUNT(t.id) as total_tickets, COALESCE(SUM(t.precio), 0) as total_recaudado FROM usuarios u LEFT JOIN tickets t ON u.id = t.vendedor_id WHERE t.estado = 'Pagado' AND t.precio > 0 GROUP BY u.id, u.email, u.rol, u.nombre, u.apellido, u.whatsapp ORDER BY total_tickets DESC`);
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

// --- RUTA ESTADÍSTICAS: AFORO Y ARQUEO ---
app.get('/api/estadisticas/:evento_id', verificarToken, async (req, res) => {
    if (req.usuario.rol !== 'Fundador' && req.usuario.rol !== 'Admin') return res.status(403).json({ error: 'Sin permisos' });
    try {
        const aforo = await pool.query(`
            SELECT sector, COUNT(*) as total_emitidos, SUM(CASE WHEN estado = 'Usado' THEN 1 ELSE 0 END) as ingresados
            FROM tickets WHERE evento_id = $1 AND estado IN ('Pagado', 'Usado') GROUP BY sector
        `, [req.params.evento_id]);

        const arqueo = await pool.query(`
            SELECT u.nombre, u.apellido, u.rol, COUNT(t.id) as cantidad, SUM(t.precio) as total_efectivo
            FROM tickets t JOIN usuarios u ON t.vendedor_id = u.id
            WHERE t.evento_id = $1 AND t.pago_manual = true AND t.precio > 0 AND t.estado IN ('Pagado', 'Usado')
            GROUP BY u.id, u.nombre, u.apellido, u.rol
        `, [req.params.evento_id]);

        const frees = await pool.query(`
            SELECT u.nombre, u.apellido, u.rol, COUNT(t.id) as cantidad
            FROM tickets t JOIN usuarios u ON t.vendedor_id = u.id
            WHERE t.evento_id = $1 AND t.precio = 0 AND t.estado IN ('Pagado', 'Usado')
            GROUP BY u.id, u.nombre, u.apellido, u.rol
        `, [req.params.evento_id]);

        res.json({ aforo: aforo.rows, arqueo: arqueo.rows, frees: frees.rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTAS DE EVENTOS, SECTORES Y PREVENTAS ---
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
    let { evento_id, sector_id, cantidad, pago_manual, email_comprador, es_free } = req.body; 
    const vendedor_id = req.usuario.id; 
    cantidad = parseInt(cantidad) || 1;

    if (req.usuario.rol === 'Vendedor' || req.usuario.rol === 'Boleteria') {
      if (!req.usuario.evento_id) return res.status(403).json({ error: 'Usuario sin evento.' });
      evento_id = req.usuario.evento_id;
    }

    const sectorData = await pool.query('SELECT * FROM sectores WHERE id = $1', [sector_id]);
    if (sectorData.rows.length === 0) return res.status(400).json({ error: 'Sector no encontrado' });
    const sector = sectorData.rows[0];

    const preventaQuery = await pool.query('SELECT * FROM preventas WHERE evento_id = $1 AND sector_id = $2 AND (fecha_limite IS NULL OR fecha_limite >= NOW()) ORDER BY fecha_limite ASC LIMIT 1', [evento_id, sector_id]);
    if (preventaQuery.rows.length === 0) return res.status(400).json({ error: 'No hay preventas activas' });
    
    let precioTicket = preventaQuery.rows[0].precio;
    let nombreTanda = preventaQuery.rows[0].nombre;

    if (es_free && (req.usuario.rol === 'Fundador' || req.usuario.rol === 'Admin')) {
        precioTicket = 0;
        nombreTanda = 'Free Pass';
        pago_manual = true; 
    }

    const eventoQuery = await pool.query('SELECT nombre FROM eventos WHERE id = $1', [evento_id]);
    const eventoNombre = eventoQuery.rows[0] ? eventoQuery.rows[0].nombre : 'Evento Hype';

    const linksGenerados = [];
    const estado_inicial = pago_manual ? 'Pagado' : 'Pendiente';

    for(let i = 0; i < cantidad; i++) {
        const codigo_qr = crypto.randomUUID(); 
        
        await pool.query(
          'INSERT INTO tickets (evento_id, vendedor_id, codigo_qr, precio, sector, estado, fecha_venta, email_comprador) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)',
          [evento_id, vendedor_id, codigo_qr, precioTicket, sector.nombre, estado_inicial, email_comprador || null]
        );
        
        const linkEntrada = `https://hypevenue.up.railway.app/comprar/${codigo_qr}`;
        linksGenerados.push(linkEntrada);

        if (pago_manual && email_comprador) {
            const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${codigo_qr}`;
            const correoData = {
                sender: { email: "hypevenuesp@gmail.com", name: "Hype Venue" },
                to: [{ email: email_comprador }],
                subject: `Tu entrada para ${eventoNombre} está lista`,
                htmlContent: `<div style="font-family: Arial, sans-serif; text-align: center; padding: 30px; background: #111; color: #fff; border-radius: 10px;">
                        <h1 style="color: #00ffcc;">¡Generación Exitosa!</h1>
                        <p>Ya tenés tu lugar asegurado en el sector <strong>${sector.nombre}</strong>.</p>
                        <div style="background: #fff; padding: 15px; border-radius: 10px; display: inline-block; margin: 20px 0;">
                            <img src="${qrImageUrl}" alt="Tu Código QR" style="display: block; width: 200px; height: 200px;">
                        </div>
                        <p>Mostrá este QR en puerta.</p>
                        <a href="${linkEntrada}" style="background: #00ffcc; color: #000; padding: 15px 25px; text-decoration: none; font-weight: bold; border-radius: 5px; display: inline-block; margin-top: 20px;">VER MI ENTRADA ONLINE</a>
                       </div>`
            };

            axios.post('https://api.brevo.com/v3/smtp/email', correoData, {
                headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' }
            }).catch(err => console.error('Error Brevo manual:', err.message));
        }
    }

    res.json({ links: linksGenerados, precio: precioTicket, tanda: nombreTanda, cantidad });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTA INICIAR PAGO (SIMULADOR) ---
app.post('/api/iniciar-pago', async (req, res) => {
  try {
      const { codigo, email } = req.body;
      const ticketQ = await pool.query('UPDATE tickets SET email_comprador = $1 WHERE codigo_qr = $2 AND estado = $3 RETURNING *', [email, codigo, 'Pendiente']);
      if (ticketQ.rows.length === 0) return res.status(400).json({ error: 'Ticket no válido o ya pagado.' });
      res.json({ url: `/simulador-pago/${codigo}` }); 
  } catch (err) { res.status(500).json({ error: 'Error del servidor.' }); }
});

// --- WEBHOOK DE NAVE ---
app.post('/api/webhooks/nave', async (req, res) => {
    try {
        const { status, reference } = req.body; 
        if (status === 'approved' || status === 'paid') {
            const result = await pool.query('UPDATE tickets SET estado = $1 WHERE codigo_qr = $2 AND estado = $3 RETURNING *', ['Pagado', reference, 'Pendiente']);
            
            if (result.rows.length > 0) {
                const ticketPagado = result.rows[0];
                const eventoQuery = await pool.query('SELECT nombre FROM eventos WHERE id = $1', [ticketPagado.evento_id]);
                const eventoNombre = eventoQuery.rows[0] ? eventoQuery.rows[0].nombre : 'Evento Hype';

                const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${ticketPagado.codigo_qr}`;
                const linkEntrada = `https://hypevenue.up.railway.app/comprar/${ticketPagado.codigo_qr}`;
                
                const correoData = {
                    sender: { email: "hypevenuesp@gmail.com", name: "Hype Venue" }, 
                    to: [{ email: ticketPagado.email_comprador }],
                    subject: `Tu entrada para ${eventoNombre} está lista`,
                    htmlContent: `<div style="font-family: Arial, sans-serif; text-align: center; padding: 30px; background: #111; color: #fff; border-radius: 10px;">
                            <h1 style="color: #00ffcc;">¡Pago Exitoso!</h1>
                            <p>Ya tenés tu lugar asegurado en el sector <strong>${ticketPagado.sector}</strong>.</p>
                            <div style="background: #fff; padding: 15px; border-radius: 10px; display: inline-block; margin: 20px 0;">
                                <img src="${qrImageUrl}" alt="Tu Código QR" style="display: block; width: 200px; height: 200px;">
                            </div>
                            <p>Mostrá este QR en puerta.</p>
                            <a href="${linkEntrada}" style="background: #00ffcc; color: #000; padding: 15px 25px; text-decoration: none; font-weight: bold; border-radius: 5px; display: inline-block; margin-top: 20px;">VER MI ENTRADA ONLINE</a>
                           </div>`
                };

                axios.post('https://api.brevo.com/v3/smtp/email', correoData, {
                    headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' }
                }).catch(err => console.error('Error enviando API:', err.response?.data || err.message));
            }
        }
        res.sendStatus(200);
    } catch (err) { res.sendStatus(500); }
});

// --- PANTALLA DEL SIMULADOR DE PAGO ---
app.get('/simulador-pago/:codigo', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>body{font-family:Arial;background:#000;color:#fff;text-align:center;padding:50px 20px;}h2{color:#00ffcc;}.btn{background:#00ffcc;color:#000;padding:15px;font-weight:bold;border:none;cursor:pointer;}</style></head>
        <body><h2>Entorno de Pruebas</h2><button class="btn" onclick="simular()">Simular Pago Exitoso</button>
        <script>
            async function simular() {
                const res = await fetch('/api/webhooks/nave', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reference: "${req.params.codigo}", status: "approved" }) });
                if(res.ok) window.location.href = '/comprar/${req.params.codigo}'; else alert("Error");
            }
        </script></body></html>
    `);
});

// --- RUTA ACTIVAR TICKET (Captura de datos) ---
app.post('/api/tickets/:codigo/activar', async (req, res) => {
    try {
        const { nombre, apellido, email, whatsapp, sexo, fecha_nacimiento } = req.body;
        const result = await pool.query(
            `UPDATE tickets SET nombre_comprador = $1, apellido_comprador = $2, email_comprador = $3, whatsapp_comprador = $4, sexo = $5, fecha_nacimiento = $6 
             WHERE codigo_qr = $7 AND estado = 'Pagado' RETURNING *`,
            [nombre, apellido, email, whatsapp, sexo, fecha_nacimiento, req.params.codigo]
        );
        if (result.rows.length === 0) return res.status(400).json({ error: 'Ticket inválido' });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- VISTA FINAL DEL COMPRADOR ---
app.get('/comprar/:codigo', async (req, res) => {
  try {
    const ticketQuery = await pool.query('SELECT * FROM tickets WHERE codigo_qr = $1', [req.params.codigo]);
    if (ticketQuery.rows.length === 0) return res.status(404).send('<h1>Ticket no encontrado</h1>');

    const ticket = ticketQuery.rows[0];
    const eventoQuery = await pool.query('SELECT * FROM eventos WHERE id = $1', [ticket.evento_id]);
    const evento = eventoQuery.rows[0] ? eventoQuery.rows[0].nombre : 'Evento Hype';

    // 1. SI ESTÁ PENDIENTE: Pantalla de Pago
    if (ticket.estado === 'Pendiente') {
        return res.send(`
            <!DOCTYPE html>
            <html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Pago</title>
            <style>body{font-family:Arial;background:#000;color:#fff;text-align:center;padding:40px;}.card{background:#111;padding:30px;border-radius:12px;max-width:400px;margin:auto;}input,button{width:100%;padding:12px;margin-top:15px;box-sizing:border-box;}button{background:#00ffcc;color:#000;border:none;font-weight:bold;cursor:pointer;}</style></head>
            <body><div class="card"><h2 style="color:#00ffcc;">HYPE VENUE</h2><h3>${evento} - Sector: ${ticket.sector}</h3><p>Total: <strong>$${ticket.precio}</strong></p>
            <form id="formPago"><input type="email" id="emailCompra" placeholder="tu-correo@ejemplo.com" required><button type="submit" id="btnPagar">Ir a Pagar</button></form></div>
            <script>
                document.getElementById('formPago').addEventListener('submit', async (e) => {
                    e.preventDefault(); document.getElementById('btnPagar').innerText = 'Cargando...'; document.getElementById('btnPagar').disabled = true;
                    const res = await fetch('/api/iniciar-pago', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ codigo: '${ticket.codigo_qr}', email: document.getElementById('emailCompra').value }) });
                    const data = await res.json(); if(data.url) window.location.href = data.url; else alert('Error');
                });
            </script></body></html>
        `);
    }

    // 2. SI ESTÁ PAGADO PERO SIN DATOS: Pantalla de Activación
    if (!ticket.nombre_comprador) {
         return res.send(`
            <!DOCTYPE html>
            <html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Activar Entrada</title>
            <style>body{font-family:Arial;background:#000;color:#fff;text-align:center;padding:20px;}.card{background:#111;padding:25px;border-radius:12px;max-width:400px;margin:auto;border:1px solid #00ffcc;}input,select,button{width:100%;padding:12px;margin-top:10px;box-sizing:border-box;background:#222;color:#fff;border:1px solid #444;border-radius:6px;}button{background:#00ffcc;color:#000;font-weight:bold;cursor:pointer;border:none;margin-top:20px;}</style></head>
            <body><div class="card"><h2 style="color:#00ffcc;margin-top:0;">ACTIVÁ TU ENTRADA</h2><p style="font-size:14px;color:#ccc;">Completá tus datos para ver el QR.</p>
            <form id="formActivar">
                <input type="text" id="nombre" placeholder="Nombre" required>
                <input type="text" id="apellido" placeholder="Apellido" required>
                <input type="email" id="email" placeholder="Email" value="${ticket.email_comprador || ''}" required>
                <input type="tel" id="whatsapp" placeholder="WhatsApp (Ej: +549...)" required>
                <select id="sexo" required><option value="">Sexo...</option><option value="Masculino">Masculino</option><option value="Femenino">Femenino</option><option value="Otro">Otro</option></select>
                <input type="date" id="fecha_nac" required>
                <button type="submit" id="btnActivar">Generar mi QR</button>
            </form></div>
            <script>
                document.getElementById('formActivar').addEventListener('submit', async (e) => {
                    e.preventDefault(); document.getElementById('btnActivar').innerText = 'Generando...'; document.getElementById('btnActivar').disabled = true;
                    const body = { nombre: document.getElementById('nombre').value, apellido: document.getElementById('apellido').value, email: document.getElementById('email').value, whatsapp: document.getElementById('whatsapp').value, sexo: document.getElementById('sexo').value, fecha_nacimiento: document.getElementById('fecha_nac').value };
                    const res = await fetch('/api/tickets/${ticket.codigo_qr}/activar', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) });
                    if(res.ok) window.location.reload(); else { alert('Error al activar'); document.getElementById('btnActivar').innerText = 'Generar mi QR'; document.getElementById('btnActivar').disabled = false; }
                });
            </script></body></html>
        `);
    }

    // 3. SI ESTÁ PAGADO Y ACTIVADO: Se muestra el QR
    res.send(`
      <!DOCTYPE html>
      <html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Tu Entrada</title>
      <style>body{font-family:Arial;background:#000;color:#fff;text-align:center;padding:20px;}.card{background:#111;padding:30px;border-radius:12px;max-width:400px;margin:auto;border:2px solid #00ffcc;}h1{color:#00ffcc;margin-bottom:5px;}</style></head>
      <body><div class="card"><div style="background:#00ffcc;color:#000;display:inline-block;padding:5px 15px;border-radius:20px;font-weight:bold;margin-bottom:10px;">✔ HABILITADO</div>
      <h1>HYPE VENUE</h1><h3>${evento}</h3>
      <p style="margin:5px 0;color:#00ffcc;font-size:18px;"><strong>${ticket.nombre_comprador.toUpperCase()} ${ticket.apellido_comprador.toUpperCase()}</strong></p>
      <p style="margin:5px 0;">Sector: <strong>${ticket.sector}</strong></p>
      <div style="background:#fff;padding:15px;border-radius:10px;display:inline-block;margin:15px 0;"><img src="https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${ticket.codigo_qr}" style="width:200px;height:200px;display:block;"></div>
      <p style="color:#ffaa00;font-weight:bold;">Presentá este QR en puerta junto a tu DNI.</p></div></body></html>
    `);
  } catch (err) { res.status(500).send('Error'); }
});

// --- RUTAS PARA ESCÁNER EN PUERTA ---
app.get('/api/escanear/:codigo', async (req, res) => {
    try {
        const query = await pool.query('SELECT * FROM tickets WHERE codigo_qr = $1', [req.params.codigo]);
        if (query.rows.length === 0) return res.status(404).json({ error: 'Ticket no encontrado' });
        res.json(query.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/escanear/:codigo/usar', async (req, res) => {
    try {
        const result = await pool.query("UPDATE tickets SET estado = 'Usado' WHERE codigo_qr = $1 AND estado = 'Pagado' RETURNING *", [req.params.codigo]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'El ticket no está Pagado o ya fue Usado' });
        res.json({ mensaje: 'Acceso autorizado', ticket: result.rows[0] });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/boleteria', (req, res) => res.sendFile(path.join(__dirname, 'boleteria.html')));
app.get('/scanner', (req, res) => res.sendFile(path.join(__dirname, 'scanner.html')));

const PORT = process.env.PORT || 3000;

setInterval(async () => {
    try { await pool.query("DELETE FROM tickets WHERE estado = 'Pendiente' AND fecha_venta < NOW() - INTERVAL '24 hours'"); } 
    catch (err) { console.error('Error limpieza:', err.message); }
}, 3600000); 

app.listen(PORT, () => console.log(`Puerto ${PORT}`));
