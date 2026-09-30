const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// Conexión a tu base de datos en Railway
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Ruta para crear un evento
app.post('/api/eventos', async (req, res) => {
  try {
    const { nombre, fecha } = req.body;
    const nuevoEvento = await pool.query(
      'INSERT INTO eventos (nombre, fecha) VALUES ($1, $2) RETURNING *',
      [nombre, fecha]
    );
    res.json(nuevoEvento.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Error en el servidor');
  }
});

// Ruta para ver todos los eventos
app.get('/api/eventos', async (req, res) => {
  try {
    const todosLosEventos = await pool.query('SELECT * FROM eventos');
    res.json(todosLosEventos.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Error en el servidor');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
