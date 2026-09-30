const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.post('/api/eventos', async (req, res) => {
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

// NUEVO: Ruta para eliminar eventos
app.delete('/api/eventos/:id', async (req, res) => {
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
