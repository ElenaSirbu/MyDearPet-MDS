const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const ejs = require('ejs');
const app = express();
const port = 3000;

// Middleware pentru a procesa corpul cererilor HTTP
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'src')));

app.set('view engine', 'ejs'); 
app.set('views', path.join(__dirname, 'views')); 

// Middleware pentru sesiuni
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: true,
}));

function requireLogin(req, res, next) {
    if (!req.session.user) {
      return res.redirect('/login');
    }
    next();
  }
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


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'src', 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'src', 'register.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'src', 'login.html'));
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'src', 'dashboard.html'));
});


// Ruta pentru inregistrare
app.post('/register', async (req, res) => {
  const { username, password, email, full_name, address, phone_number } = req.body;

  if (!username || !password || !email) {
    return res.status(400).send('Toate câmpurile obligatorii trebuie completate');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    con.query('INSERT INTO users (username, password, email, full_name, address, phone_number) VALUES (?, ?, ?, ?, ?, ?)',
      [username, hashedPassword, email, full_name, address, phone_number],
      (err, result) => {
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

// Ruta pentru afisarea si actualizarea profilului utilizatorului
app.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const userId = req.session.user.id;

    con.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Eroare la interogare:', err);
            return res.status(500).send('Eroare la interogare');
        }

        if (results.length === 0) {
            return res.status(404).send('Utilizatorul nu există');
        }

        const user = results[0];

        // Transmitem datele utilizatorului ca variabile in sablon
        res.render('profile', { user });
    });
});


app.post('/profile', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id;
  const { username, email } = req.body;

  con.query('SELECT * FROM users WHERE (username = ? OR email = ?) AND id <> ?', [username, email, userId], async (err, results) => {
    if (err) {
      console.error('Eroare la interogare:', err);
      return res.status(500).send('Eroare la interogare');
    }

    if (results.length > 0) {
      return res.status(400).send('Numele de utilizator sau emailul există deja');
    }

    const { full_name, address, phone_number } = req.body;
    con.query('UPDATE users SET username = ?, email = ?, full_name = ?, address = ?, phone_number = ? WHERE id = ?',
      [username, email, full_name, address, phone_number, userId],
      (err, result) => {
        if (err) {
          console.error('Eroare la actualizare:', err);
          return res.status(500).send('Eroare la actualizare');
        }

        // Actualizam si sesiunea utilizatorului cu noile date
        req.session.user.username = username;
        req.session.user.email = email;
        req.session.user.full_name = full_name;
        req.session.user.address = address;
        req.session.user.phone_number = phone_number;

        res.redirect('/profile');
      });
  });
});
// Ruta pentru a obtine datele utilizatorului in format JSON
app.get('/profileData', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Utilizatorul nu este autentificat' });
    }

    const userId = req.session.user.id;

    con.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Eroare la interogare:', err);
            return res.status(500).json({ error: 'Eroare la interogare' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Utilizatorul nu există' });
        }

        const user = results[0];
        res.json({
            username: user.username,
            email: user.email,
            full_name: user.full_name,
            address: user.address,
            phone_number: user.phone_number
        });
    });
});

// Ruta pentru actualizarea profilului utilizatorului
app.post('/updateProfile', (req, res) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
  
    const userId = req.session.user.id;
    const { username, email, full_name, address, phone_number } = req.body;
  
    if (!username || !email || !full_name) {
      return res.status(400).send('Toate câmpurile obligatorii trebuie completate');
    }
  
    con.query(
      'UPDATE users SET username = ?, email = ?, full_name = ?, address = ?, phone_number = ? WHERE id = ?',
      [username, email, full_name, address, phone_number, userId],
      (err, result) => {
        if (err) {
          console.error('Eroare la actualizare:', err);
          return res.status(500).send('Eroare la actualizare');
        }
  
        req.session.user.username = username;
        req.session.user.email = email;
        req.session.user.full_name = full_name;
        req.session.user.address = address;
        req.session.user.phone_number = phone_number;
  
        res.redirect('/profile');
      }
    );
  });

  app.get('/add-pet', requireLogin, (req, res) => {
    res.render('add-pet');
  });

  app.post('/add-pet', requireLogin, (req, res) => {
    const { species, breed, age, description, photo_url } = req.body;
    con.query('INSERT INTO animals (species, breed, age, description, photo_url) VALUES (?, ?, ?, ?, ?)',
      [species, breed, age, description, photo_url],
      (err, result) => {
        if (err) {
          console.error('Eroare la adăugarea animalului:', err);
          return res.status(500).send('Eroare la adăugarea animalului');
        }
        res.redirect('/explore');
      });
  });
  
// Ruta pentru a afisa formularul de adaugare a unui animal
app.get('/pets/add', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.render('add-pet');
});

// Ruta pentru a procesa adaugarea unui animal
app.post('/pets/add', (req, res) => {
    const { species, breed, age, description, photo_url } = req.body;
    const query = 'INSERT INTO animals (species, breed, age, description, photo_url) VALUES (?, ?, ?, ?, ?)';
    con.query(query, [species, breed, age, description, photo_url], (err, results) => {
        if (err) {
            console.error('Eroare la inserare:', err);
            return res.status(500).send('Eroare la inserare');
        }
        res.redirect('/explore');
    });
});

// Ruta pentru a obtine lista de animale disponibile
app.get('/explore', (req, res) => {
    const query = 'SELECT * FROM animals ORDER BY animal_id DESC';
    con.query(query, (err, results) => {
        if (err) {
            console.error('Eroare la interogare:', err);
            return res.status(500).send('Eroare la interogare');
        }
        res.render('explore', { pets: results });
    });
});

// Ruta pentru filtrarea animalelor
app.get('/pets/filter', (req, res) => {
    const { species, breed, age } = req.query;
    let query = 'SELECT * FROM animals WHERE 1=1';
    const filters = [];

    if (species) {
        filters.push(`species = ${mysql.escape(species)}`);
    }
    if (breed) {
        filters.push(`breed = ${mysql.escape(breed)}`);
    }
    if (age) {
        filters.push(`age = ${mysql.escape(age)}`);
    }

    if (filters.length > 0) {
        query += ' AND ' + filters.join(' AND ');
    }

    query += ' ORDER BY animal_id DESC';

    con.query(query, (err, results) => {
        if (err) {
            console.error('Eroare la interogare:', err);
            return res.status(500).send('Eroare la interogare');
        }
        res.render('explore', { pets: results });
    });
});

// Ruta pentru a obtine detalii despre un animal
app.get('/pets/:id', (req, res) => {
    const animalId = req.params.id;
    con.query('SELECT * FROM animals WHERE animal_id = ?', [animalId], (err, results) => {
        if (err) {
            console.error('Eroare la interogare:', err);
            return res.status(500).send('Eroare la interogare');
        }
        if (results.length === 0) {
            return res.status(404).send('Animalul nu există');
        }
        res.render('animal_detail', { pet: results[0] });
    });
});

// app.js

// Ruta pentru pagina my-pets
app.get('/my-pets', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const userId = req.session.user.id;

    // Interogare pentru a obtine animalele favorite ale utilizatorului
    con.query('SELECT * FROM animals WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error querying favorite pets:', err);
            return res.status(500).send('Error querying favorite pets');
        }

        // Afisam pagina my-pets.ejs si transmitem lista de animale favorite
        res.render('my-pets', { favoritePets: results });
    });
});


// Pornirea serverului
app.listen(port, () => {
  console.log(`Serverul rulează la adresa http://localhost:${port}`);
});
