const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
const port = 3000;

// Middleware pentru a procesa corpul cererilor HTTP
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('src'));

// Middleware pentru sesiuni
app.use(session({
  secret: 'secretKey', 
  resave: false,
  saveUninitialized: true,
}));

// Configurarea conexiunii la baza de date MySQL
const con = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'mydearpet'
});

// Conectarea la baza de date
con.connect(err => {
  if (err) {
    console.error('Eroare la conectare la baza de date:', err);
    return;
  }
  console.log('Conectat la baza de date MySQL');
});

// Paginile de inregistrare si autentificare
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/src/index.html');
});

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/src/register.html');
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/src/login.html');
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.sendFile(__dirname + '/src/dashboard.html');
});

// Ruta pentru inregistrare
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Toate câmpurile sunt obligatorii');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    con.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
      if (err) {
        console.error('Eroare la înregistrare:', err);
        return res.status(500).send('Eroare la înregistrare');
      }
      res.status(201).send('Utilizator înregistrat cu succes');
    });
  } catch (error) {
    console.error('Eroare la hashing:', error);
    res.status(500).send('Eroare la hashing');
  }
});

// Ruta pentru autentificare
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Toate câmpurile sunt obligatorii');
  }

  con.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) {
      console.error('Eroare la interogare:', err);
      return res.status(500).send('Eroare la autentificare');
    }

    if (results.length === 0) {
      return res.status(400).send('Utilizatorul nu există');
    }

    const user = results[0];

    try {
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        req.session.user = user;
        return res.redirect('/dashboard');
      } else {
        res.status(400).send('Parolă incorectă');
      }
    } catch (error) {
      console.error('Eroare la comparare:', error);
      res.status(500).send('Eroare la comparare');
    }
  });
});

// Ruta pentru deconectare
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Eroare la deconectare');
    }
    res.redirect('/');
  });
});

// Pornirea serverului
app.listen(port, () => {
  console.log(`Serverul rulează la adresa http://localhost:${port}`);
});
