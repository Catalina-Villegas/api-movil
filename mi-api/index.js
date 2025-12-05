const express = require('express');
const cors = require('cors');
const pool = require('./db');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

// Crear tabla automáticamente
const iniciarDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        correo VARCHAR(150) UNIQUE NOT NULL,
        contrasena VARCHAR(200) NOT NULL,
        fecha VARCHAR(50) NOT NULL,
        nivel INTEGER DEFAULT 0
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tareas (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER NOT NULL,
        descripcion TEXT NOT NULL,
        puntos INTEGER NOT NULL,
        completado INTEGER DEFAULT 0,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
      );
    `);

    console.log("Tablas 'usuarios' y 'tareas' verificadas.");
  } catch (err) {
    console.error("Error DB:", err);
  }
};
iniciarDB();

// RUTAS USUARIOS
app.get('/usuarios', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM usuarios');
    res.json(result.rows);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.get('/usuarios/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.get('/usuarios/email/:correo', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE correo = $1',
      [req.params.correo]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    const usuario = result.rows[0];
    delete usuario.contrasena; // Nunca devolver la contraseña
    res.json(usuario);

  } catch (err) {
    res.status(500).send(err);
  }
});

app.post('/usuarios', async (req, res) => {
  try {
    const { nombre, correo, contrasena, fecha, nivel } = req.body;

    const result = await pool.query(
      `INSERT INTO usuarios (nombre, correo, contrasena, fecha, nivel)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [nombre, correo, contrasena, fecha, nivel ?? 0]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.put('/usuarios/:id', async (req, res) => {
  try {
    const { nombre, correo, contrasena, fecha, nivel } = req.body;

    const result = await pool.query(
      `UPDATE usuarios 
       SET nombre = $1, correo = $2, contrasena = $3, fecha = $4, nivel = $5
       WHERE id = $6
       RETURNING *`,
      [nombre, correo, contrasena, fecha, nivel, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.delete('/usuarios/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM usuarios WHERE id = $1 RETURNING *',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json({ message: 'Usuario eliminado' });
  } catch (err) {
    res.status(500).send(err);
  }
});

//RUTAS TAREAS
app.get('/tareas', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tareas');
    res.json(result.rows);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.get('/tareas/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tareas WHERE id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.get('/tareas/usuario/:usuario_id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tareas WHERE usuario_id = $1',
      [req.params.usuario_id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.post('/tareas', async (req, res) => {
  try {
    const { usuario_id, descripcion, puntos, completado } = req.body;

    const result = await pool.query(
      `INSERT INTO tareas (usuario_id, descripcion, puntos, completado)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [usuario_id, descripcion, puntos, completado ?? 0]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.put('/tareas/:id', async (req, res) => {
  try {
    const { usuario_id, descripcion, puntos, completado } = req.body;

    const result = await pool.query(
      `UPDATE tareas
       SET usuario_id = $1, descripcion = $2, puntos = $3, completado = $4
       WHERE id = $5
       RETURNING *`,
      [usuario_id, descripcion, puntos, completado, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.delete('/tareas/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM tareas WHERE id = $1 RETURNING *',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    res.json({ message: 'Tarea eliminada' });
  } catch (err) {
    res.status(500).send(err);
  }
});

// Ruta para Login
app.post('/login', async (req, res) => {
  try {
    const { correo, contrasena } = req.body;

    const result = await pool.query(
      'SELECT * FROM usuarios WHERE correo = $1',
      [correo]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const usuario = result.rows[0];

    if (usuario.contrasena !== contrasena) {
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    } 
    
    // Quitamos la contraseña de la respuesta por seguridad
    delete usuario.contrasena;
    res.json({ message: 'Login exitoso', usuario });

  } catch (err) {
    res.status(500).send(err);
  }
});





app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});