const express = require('express');
const cors = require('cors');
const pool = require('./db');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

const diferenciaEnDias = (fecha1, fecha2) => {
  const unDia = 1000 * 60 * 60 * 24;
  const diferencia = Math.round(Math.abs((fecha1 - fecha2) / unDia));
  return diferencia;
};

const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET || 'SECRETO_POR_DEFECTO_CAMBIAR', (err, usuario) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.usuario = usuario;
    next();
  });
};

// --- INICIO DE LA CORRECCIÓN: Lógica para actualizar la tabla existente ---
const iniciarDB = async () => {
  try {
    // 1. Asegurarse de que la tabla 'usuarios' existe (sin las nuevas columnas)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        correo VARCHAR(150) UNIQUE NOT NULL,
        contrasena VARCHAR(200) NOT NULL,
        fecha VARCHAR(50) NOT NULL,
        nivel INTEGER DEFAULT 0,
        rol VARCHAR(20) NOT NULL DEFAULT 'usuario'
      );
    `);

    // 2. Comprobar si la columna 'racha' existe y añadirla si no
    const rachaCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name='usuarios' AND column_name='racha';
    `);
    if (rachaCheck.rows.length === 0) {
      await pool.query('ALTER TABLE usuarios ADD COLUMN racha INTEGER DEFAULT 0;');
      console.log("Columna 'racha' añadida a la tabla 'usuarios'.");
    }

    // 3. Comprobar si la columna 'ultima_conexion' existe y añadirla si no
    const ultimaConexionCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name='usuarios' AND column_name='ultima_conexion';
    `);
    if (ultimaConexionCheck.rows.length === 0) {
      await pool.query('ALTER TABLE usuarios ADD COLUMN ultima_conexion DATE;');
      console.log("Columna 'ultima_conexion' añadida a la tabla 'usuarios'.");
    }

    // 4. Asegurarse de que la tabla 'tareas' existe
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
    console.log("Tablas 'usuarios' y 'tareas' verificadas y actualizadas.");
  } catch (err) {
    console.error("Error al iniciar la base de datos:", err);
  }
};
// --- FIN DE LA CORRECCIÓN ---
iniciarDB();

app.post('/usuarios', async (req, res) => {
  try {
    const { nombre, correo, contrasena, fecha } = req.body;
    const salt = await bcrypt.genSalt(10);
    const contrasenaHasheada = await bcrypt.hash(contrasena, salt);

    const result = await pool.query(
      `INSERT INTO usuarios (nombre, correo, contrasena, fecha)
       VALUES ($1, $2, $3, $4)
       RETURNING id, nombre, correo, fecha, nivel, rol, racha`,
      [nombre, correo, contrasenaHasheada, fecha]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
    }
    console.error("Error al registrar:", err);
    res.status(500).json({ message: 'Error interno al registrar el usuario.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { correo, contrasena } = req.body;
    const result = await pool.query('SELECT * FROM usuarios WHERE correo = $1', [correo]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }

    let usuario = result.rows[0];
    const esContrasenaValida = await bcrypt.compare(contrasena, usuario.contrasena);

    if (!esContrasenaValida) {
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }

    if (usuario.rol === 'superuser') {
      const hoy = new Date();
      const ultimaConexion = usuario.ultima_conexion ? new Date(usuario.ultima_conexion) : null;
      let nuevaRacha = usuario.racha || 0;

      if (ultimaConexion) {
        const diasDesdeUltimaConexion = diferenciaEnDias(hoy, ultimaConexion);
        if (diasDesdeUltimaConexion === 1) {
          nuevaRacha++;
        } else if (diasDesdeUltimaConexion > 1) {
          nuevaRacha = 1;
        }
      } else {
        nuevaRacha = 1;
      }
      
      const updateResult = await pool.query(
        'UPDATE usuarios SET racha = $1, ultima_conexion = $2 WHERE id = $3 RETURNING *',
        [nuevaRacha, hoy.toISOString().split('T')[0], usuario.id]
      );
      usuario = updateResult.rows[0];
    }

    const payload = { id: usuario.id, rol: usuario.rol };
    const token = jwt.sign(payload, process.env.JWT_SECRET || 'SECRETO_POR_DEFECTO_CAMBIAR', { expiresIn: '24h' });

    delete usuario.contrasena;

    res.json({
      message: 'Inicio de sesión exitoso',
      token: token,
      usuario: usuario
    });
  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});


app.get('/usuarios', verificarToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nombre, correo, fecha, nivel, rol, racha FROM usuarios');
    res.json(result.rows);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.get('/usuarios/:id', verificarToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, correo, fecha, nivel, rol, racha FROM usuarios WHERE id = $1',
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

app.get('/usuarios/email/:correo', verificarToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, correo, fecha, nivel, rol, racha FROM usuarios WHERE correo = $1',
      [req.params.correo]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.patch('/usuarios/admin/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
  }

  try {
    const { id } = req.params;
    let { nombre, correo, fecha, nivel, rol, contrasena } = req.body;

    if (!['admin', 'moderador', 'usuario', 'superuser'].includes(rol)) {
        return res.status(400).json({ message: 'Rol no válido.' });
    }

    let query;
    let values;

    if (contrasena && contrasena.trim() !== '') {
      const salt = await bcrypt.genSalt(10);
      const contrasenaHasheada = await bcrypt.hash(contrasena, salt);
      query = `UPDATE usuarios SET nombre = $1, correo = $2, fecha = $3, nivel = $4, rol = $5, contrasena = $6 WHERE id = $7 RETURNING id, nombre, correo, fecha, nivel, rol, racha`;
      values = [nombre, correo, fecha, nivel, rol, contrasenaHasheada, id];
    } else {
      query = `UPDATE usuarios SET nombre = $1, correo = $2, fecha = $3, nivel = $4, rol = $5 WHERE id = $6 RETURNING id, nombre, correo, fecha, nivel, rol, racha`;
      values = [nombre, correo, fecha, nivel, rol, id];
    }
    
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: 'El correo electrónico ya está en uso por otro usuario.' });
    }
    console.error("Error en PATCH /usuarios/admin:", err);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

app.patch('/usuarios/moderador/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'moderador' && req.usuario.rol !== 'admin') {
    return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de moderador.' });
  }

  try {
    const { id } = req.params;
    const { nombre, fecha } = req.body;

    const result = await pool.query(
      `UPDATE usuarios SET nombre = $1, fecha = $2 WHERE id = $3 RETURNING id, nombre, correo, fecha, nivel, rol, racha`,
      [nombre, fecha, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error en PATCH /usuarios/moderador:", err);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

app.delete('/usuarios/:id', verificarToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ message: 'Acceso denegado.' });
  }
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

app.patch('/tareas/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const allowedUpdates = ['usuario_id', 'descripcion', 'puntos', 'completado'];
    const queryParts = [];
    const values = [];
    let valueIndex = 1;

    for (const key in updates) {
      if (allowedUpdates.includes(key)) {
        queryParts.push(`${key} = $${valueIndex++}`);
        values.push(updates[key]);
      }
    }

    if (queryParts.length === 0) {
      return res.status(400).json({ message: 'No hay campos válidos para actualizar.' });
    }

    values.push(id);
    const queryString = `UPDATE tareas SET ${queryParts.join(', ')} WHERE id = $${valueIndex} RETURNING *`;
    
    const result = await pool.query(queryString, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error en PATCH /tareas/:id:", err);
    res.status(500).json({ message: 'Error interno del servidor.' });
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
