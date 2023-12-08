const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

exports.login = (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username })
    .then((user) => {
      if (user) {
        // Compara la contraseña encriptada almacenada con la proporcionada
        bcrypt.compare(password, user.password, (err, result) => {
          if (result) {
            // Genera un token JWT
            const token = jwt.sign({ userId: user._id, username: user.username }, 'secretKey', { expiresIn: '1h' });
            
            // Devuelve el token y la información del usuario
            res.json({ message: 'Inicio de sesión exitoso', user, token });
          } else {
            res.status(401).json({ message: 'Credenciales inválidas' });
          }
        });
      } else {
        res.status(401).json({ message: 'Credenciales inválidas' });
      }
    })
    .catch((error) => {
      res.status(500).json({ error: error.message });
    });
};

exports.register = (req, res) => {
  const { username, password } = req.body;

  // Encripta la contraseña antes de guardarla en la base de datos
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    User.findOne({ username })
      .then((existingUser) => {
        if (existingUser) {
          res.status(400).json({ message: 'El nombre de usuario ya está en uso' });
        } else {
          // Crea un nuevo usuario con la contraseña encriptada
          const newUser = new User({ username, password: hash });

          // Guarda el nuevo usuario en la base de datos
          newUser.save()
            .then((user) => {
              // Genera un token JWT después de registrar al usuario
              const token = jwt.sign({ userId: user._id, username: user.username }, 'secretKey', { expiresIn: '1h' });
              
              // Devuelve el token y la información del usuario
              res.status(201).json({ message: 'Usuario registrado exitosamente', user, token });
            })
            .catch((error) => {
              res.status(500).json({ error: error.message });
            });
        }
      })
      .catch((error) => {
        res.status(500).json({ error: error.message });
      });
  });
};
