const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const PDFDocument = require('pdfkit'); // Importa PDFKit
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();
timezone: 'America/Tijuana'
const app = express();
const PORT = 3000;

// Configuración de la conexión a la base de datos
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'inventario_farmacia',
});

// Conexión a la base de datos
db.connect((err) => {
  if (err) {
    console.error('Error conectando a la base de datos:', err);
    process.exit(1);
  }
  console.log('Conexión a la base de datos exitosa.');
});

// Configuración de la sesión
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

app.use(express.urlencoded({ extended: true }));

// Función de autenticación
function requireLogin(req, res, next) {
  if (!req.session.user) { // Verifica si la sesión del usuario está activa
    return res.redirect('/login.html'); // Redirige al login
  }
  next();
}


// Función para verificar si el usuario tiene uno de los roles permitidos
function requireRole(...roles) {
  return (req, res, next) => {
    if (req.session.user && roles.includes(req.session.user.tipo_usuario)) {
      next();
    } else {
      res.status(403).send("Acceso denegado");
    }
  };
}

app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Servir archivos estáticos (HTML)
app.use(express.static(path.join(__dirname, 'public'))); 

// Registro de usuario
app.post('/registrar', (req, res) => {
  const { nombre_usuario, password_hash, codigo_acceso } = req.body;

  console.log('Datos recibidos:', req.body); // Verifica los datos que vienen del formulario
  console.log('Código de acceso:', codigo_acceso); // Verifica específicamente el código

  const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
  db.query(query, [codigo_acceso], (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err);
      return res.status(500).send('Error del servidor');
    }
    if (results.length === 0) {
      console.log('Código no encontrado:', codigo_acceso);
      return res.send('Código de acceso inválido');
    }

    const tipo_usuario = results[0].tipo_usuario;
    const hashedPassword = bcrypt.hashSync(password_hash, 10);

    const insertUser = 'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)';
    db.query(insertUser, [nombre_usuario, hashedPassword, tipo_usuario], (err) => {
      if (err) {
        console.error('Error al registrar usuario:', err);
        return res.send('Error al registrar usuario');
      }
      res.redirect('/login.html');
    });
  });
});


// Ruta para iniciar sesión
app.post('/login', (req, res) => {
  const { nombre_usuario, password } = req.body;
  
  const query = 'SELECT * FROM usuarios WHERE nombre_usuario = ?';
  db.query(query, [nombre_usuario], (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).send('Usuario no encontrado');
    }

    const user = results[0];

    // Compara la contraseña ingresada con la almacenada
    if (bcrypt.compareSync(password, user.password_hash)) {
      req.session.userId = user.id;  // Guardar el ID del usuario en la sesión
      req.session.user = user;       // Guardar el usuario en la sesión
      return res.redirect('/');  // Redirige al inicio
    } else {
      return res.status(400).send('Contraseña incorrecta');
    }
  });
});

// Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
  res.json({ tipo_usuario: req.session.user.tipo_usuario });
});

// Configuración de multer para la carga de archivos
const upload = multer({ dest: 'uploads/' });

// Ruta para cargar archivos Excel
app.post('/upload',  upload.single('excelFile'), requireLogin, requireRole('admin'),(req, res) => {
  if (!req.file) {
    return res.status(400).send('No se ha cargado ningún archivo.');
  }

  const filePath = path.join(__dirname, 'uploads', req.file.filename);
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0]; // Usamos la primera hoja del archivo
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  // Iteramos sobre los datos del archivo Excel y los insertamos en la base de datos
  data.forEach(row => {
    const { nombre, categoria, cantidad_total, unidad, ubicacion, estado, descripcion } = row;
    const query = 'INSERT INTO medicamentos (nombre, categoria, cantidad_total, unidad, ubicacion, estado, descripcion) VALUES (?, ?, ?, ?, ?, ?, ?)'; 
    db.query(query, [nombre, categoria, cantidad_total, unidad, ubicacion, estado, descripcion], (err, result) => {
      if (err) {
        console.error('Error al insertar material:', err);
        return;
      }
      console.log('Material insertado correctamente');
    });
  });

  res.send('<h1>Archivo cargado y datos guardados</h1>');

});


// Ruta para buscar materiales 
app.get('/buscar-medicamento', requireLogin, requireRole('farmaceutico', 'admin'),(req, res) => {
  const { nombre_medicamentos_search, categoria_medicamentos_search } = req.query;

  // Construir la consulta SQL de acuerdo con los parámetros recibidos
  let query = 'SELECT * FROM medicamentos WHERE 1=1'; // Selecciona todos los materiales

  // Si se proporciona un nombre de material, filtrar por nombre
  if (nombre_medicamentos_search) {
    query += ` AND nombre LIKE ?`;
  }

  // Si se proporciona una categoría, filtrar por categoría
  if (categoria_medicamentos_search) {
    query += ` AND categoria LIKE ?`;
  }

  // Ejecutar la consulta en la base de datos
  db.query(query, [`%${nombre_medicamentos_search}%`, `%${categoria_medicamentos_search}%`], (err, results) => {
    if (err) {
      console.error('Error al obtener los Medicamentos:', err);
      return res.status(500).send('Error al obtener los Medicamentos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Resultados de Búsqueda</title>
      </head>
      <body>
        <h1>Resultados de Búsqueda</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Categoría</th>
              <th>Cantidad Total</th>
              <th>Ubicación</th>
            </tr>
          </thead>
          <tbody>
    `;

    // Mostrar los resultados de la búsqueda
    results.forEach(medicamento => {
      html += `
        <tr>
          <td>${medicamento.nombre}</td>
          <td>${medicamento.categoria}</td>
          <td>${medicamento.cantidad_total}</td>
          <td>${medicamento.ubicacion}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para obtener todos los materiales y mostrarlos en formato HTML
app.get('/Medicamentos', requireLogin, requireRole('farmaceutico', 'admin'),(req, res) => {
  const sort = req.query.sort === 'alfabetico' ? 'nombre ASC' : 'id_medicamento ASC';
  const query = `SELECT * FROM medicamentos ORDER BY ${sort}`;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener medicamentos:', err);
      return res.status(500).send('Error al obtener los medicamentos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Medicamentos Registrados</title>
      </head>
      <body>
        <h1>Medicamentos Registrados</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Categoría</th>
              <th>Cantidad Total</th>
              <th>Unidad</th>
              <th>Ubicación</th>
              <th>Estado</th>
              <th>Descripción</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(medicamento => {
      html += `
        <tr>
          <td>${medicamento.nombre}</td>
          <td>${medicamento.categoria}</td>
          <td>${medicamento.cantidad_total}</td>
          <td>${medicamento.unidad}</td>
          <td>${medicamento.ubicacion}</td>
          <td>${medicamento.estado}</td>
          <td>${medicamento.descripcion}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

//Agregar new material
app.post('/Medicamentos', requireLogin, requireRole('admin'),(req, res) => {
  const { nombre, categoria, cantidad_total, unidad, ubicacion, estado, descripcion } = req.body;

  const query = 'INSERT INTO medicamentos (nombre, categoria, cantidad_total, unidad, ubicacion, estado, descripcion) VALUES (?, ?, ?, ?, ?, ?, ?)';
  db.query(query, [nombre, categoria, cantidad_total, unidad, ubicacion, estado, descripcion], (err, result) => {
    if (err) {
      return res.status(500).send('Error al registrar medicamento');
    }
    res.send('Medicamento registrado con éxito');
  });
});

app.post('/actualizar_medicamento', requireLogin, requireRole('admin'), (req, res) => {
  const { nombre, cantidad_total } = req.body;

  // Verifica que los campos requeridos estén presentes
  if (!nombre || !cantidad_total) {
    return res.status(400).send('Faltan datos requeridos.');
  }
const query = 'UPDATE medicamentos SET cantidad_total = ? WHERE nombre = ?';

db.query(query, [cantidad_total, nombre], (err, result) => {
  if (err) {
    console.error('Error al actualizar el medicamento:', err);
    return res.status(500).send('Error al actualizar el medicamento.');
  }

  if (result.affectedRows === 0) {
    return res.status(404).send('medicamento no encontrado.');
  }

  res.send(`la cantidad para ${nombre} fue actualizado exitosamente.`);
});
});

app.post('/eliminar_medicamento', requireLogin, requireRole('admin'), (req, res) => {
  const {nombre} = req.body;

  const query = 'DELETE FROM medicamentos WHERE nombre=(?)';
  db.query(query, [nombre], (err, result) => {
    if (err) {
      return res.send('Error al eliminar el medicamento.');
    }
    res.send(`medicamento eliminado de la base de datos.`);
  });
});

app.get('/buscar-medicamentos', requireLogin, requireRole('farmaceutico', 'admin'), (req, res) => {
  const query = req.query.query; // Obtiene el término de búsqueda desde la URL

  // Consulta SQL para buscar medicamentos por nombre o categoría
  const sql = `
    SELECT nombre, categoria, cantidad_total 
    FROM medicamentos 
    WHERE nombre LIKE ? OR categoria LIKE ?
  `;

  const searchTerm = `%${query}%`; // Permite búsqueda parcial

  db.query(sql, [searchTerm, searchTerm], (err, results) => {
    if (err) {
      console.error('Error en la búsqueda de medicamentos:', err);
      return res.status(500).json({ error: 'Error en la búsqueda' });
    }

    res.json(results); // Devuelve los resultados en formato JSON
  });
});


app.get('/download-medicamentos', requireLogin, requireRole('farmaceutico','admin'), (req, res) => {
  const { type } = req.query; // Tipo de archivo: 'excel' o 'pdf'
  const sql = `SELECT * FROM medicamentos`;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error al obtener los medicamentos:', err);
      return res.status(500).send('Error al obtener los medicamentos');
    }

    if (type === 'excel') {
      // Generar archivo Excel
      const worksheet = xlsx.utils.json_to_sheet(results);
      const workbook = xlsx.utils.book_new();
      xlsx.utils.book_append_sheet(workbook, worksheet, 'Medicamentos');

      const filePath = path.join(__dirname, 'uploads', 'medicamentos.xlsx');
      xlsx.writeFile(workbook, filePath);

      res.download(filePath, 'medicamentos.xlsx', (err) => {
        if (err) console.error('Error al descargar el archivo Excel:', err);
      });

    } else if (type === 'pdf') {
      // Generar archivo PDF
      const doc = new PDFDocument();
      const filePath = path.join(__dirname, 'uploads', 'medicamentos.pdf');

      // Configurar el encabezado del archivo
      res.setHeader('Content-Disposition', 'attachment; filename="medicamentos.pdf"');
      res.setHeader('Content-Type', 'application/pdf');

      // Pipe el PDF al cliente
      doc.pipe(res);

      // Título
      doc.fontSize(18).text('Lista de Medicamentos', { align: 'center' });
      doc.moveDown();

      // Crear una tabla básica
      results.forEach((medicamento) => {
        doc
          .fontSize(12)
          .text(`Nombre: ${medicamento.nombre}`, { continued: true })
          .text(` | Categoría: ${medicamento.categoria}`, { continued: true })
          .text(` | Cantidad: ${medicamento.cantidad_total}`)
          .text(` | ubicacion: ${medicamento.ubicacion}`)
          .text(` | estado: ${medicamento.estado}`);
        doc.moveDown(0.5);
      });

      // Finalizar el PDF
      doc.end();
    } else {
      res.status(400).send('Tipo de archivo no válido. Usa ?type=excel o ?type=pdf');
    }
  });
});


// Ruta para obtener todos los materiales ordenados por cantidad
app.get('/Medicamento/cantidad', requireLogin, requireRole('admin'), (req, res) => {
  const query = 'SELECT * FROM medicamentos ORDER BY cantidad_total DESC'; // Ordenar por cantidad en orden descendente
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener medicamentos:', err);
      return res.status(500).send('Error al obtener los medicamentos.');
    }

    // Construir la respuesta en formato HTML
    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Medicamentos Ordenados por Cantidad</title>
      </head>
      <body>
        <h1>Medicamentos Ordenados por Cantidad</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Categoría</th>
              <th>Cantidad Total</th>
              <th>Ubicación</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(medicamento => {
      html += `
        <tr>
          <td>${medicamento.nombre}</td>
          <td>${medicamento.categoria}</td>
          <td>${medicamento.cantidad_total}</td>
          <td>${medicamento.ubicacion}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});


// Ruta para eliminar un material


// Iniciar sesión
app.post('/login', (req, res) => {
  const { nombre_usuario, password } = req.body;

  db.query('SELECT * FROM usuarios WHERE nombre_usuario = ?', [nombre_usuario], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).send('Usuario no encontrado.');
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (match) {
      req.session.userId = user.id;
      req.session.user = user;
      res.redirect('/');
    } else {
      res.status(400).send('Contraseña incorrecta.');
    }
  });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});
function requireLogin(req, res, next) {
  console.log(req.session); // Esto te ayuda a ver el estado de la sesión
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }
  next();
}


// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
