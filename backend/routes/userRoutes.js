const express = require('express');
const userController = require('../controllers/userController');
const router = express.Router();

// Rutas para usuarios
router.post('/login', userController.login);
router.post('/register', userController.register);

module.exports = router;
