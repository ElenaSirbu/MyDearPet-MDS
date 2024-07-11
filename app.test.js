const request = require('supertest');
const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

// Setup server for testing
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: true,
}));

// Mock database connection
const mockQuery = jest.fn();
const con = {
  query: mockQuery,
};

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

describe('User Authentication', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  test('should register a new user', async () => {
    mockQuery.mockImplementation((query, values, callback) => {
      callback(null, { affectedRows: 1 });
    });

    const response = await request(app)
      .post('/register')
      .send({
        username: 'testuser',
        password: 'testpassword',
        email: 'test@example.com',
        full_name: 'Test User',
        address: '123 Test St',
        phone_number: '1234567890'
      });

    expect(response.statusCode).toBe(201);
    expect(response.text).toBe('Utilizator înregistrat cu succes');
  });

  test('should fail to register a user with missing fields', async () => {
    const response = await request(app)
      .post('/register')
      .send({
        username: '',
        password: '',
        email: ''
      });

    expect(response.statusCode).toBe(400);
    expect(response.text).toBe('Toate câmpurile obligatorii trebuie completate');
  });

  test('should login an existing user', async () => {
    const hashedPassword = await bcrypt.hash('testpassword', 10);
    mockQuery.mockImplementation((query, values, callback) => {
      callback(null, [{ username: 'testuser', password: hashedPassword }]);
    });

    const response = await request(app)
      .post('/login')
      .send({
        username: 'testuser',
        password: 'testpassword'
      });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('/dashboard');
  });

  test('should fail to login with wrong password', async () => {
    const hashedPassword = await bcrypt.hash('testpassword', 10);
    mockQuery.mockImplementation((query, values, callback) => {
      callback(null, [{ username: 'testuser', password: hashedPassword }]);
    });
  
    const response = await request(app)
      .post('/login')
      .send({
        username: 'testuser',
        password: 'wrongpassword'
      });
  
    console.log(`Status Code: ${response.statusCode}`);
    console.log(`Response Text: ${response.text}`);
  
    expect(response.statusCode).toBe(400);
    expect(response.text).toBe('Parolă incorectă');
  });
  
  test('should fail to login non-existing user', async () => {
    mockQuery.mockImplementation((query, values, callback) => {
      callback(null, []);
    });

    const response = await request(app)
      .post('/login')
      .send({
        username: 'nonexistinguser',
        password: 'testpassword'
      });

    expect(response.statusCode).toBe(400);
    expect(response.text).toBe('Utilizatorul nu există');
  });
});
