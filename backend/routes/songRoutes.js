const express = require('express');
const router = express.Router();
const songController = require('../controllers/songController');
const upload = require('../middlewares/upload');

// Rutas para las canciones
router.post('/upload', upload, songController.uploadSong);
router.get('/', songController.getAllSongs);
router.get('/:songId', songController.getSongById);

// Añadir nuevas rutas para actualizar y eliminar canciones
router.put('/:songId', songController.updateSong);
router.delete('/:songId', songController.deleteSong);

module.exports = router;
