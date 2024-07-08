const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Middleware pentru a procesa corpul cererilor HTTP
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

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

// Pornirea serverului
app.listen(port, () => {
  console.log(`Serverul ruleaza la adresa http://localhost:${port}`);
});
