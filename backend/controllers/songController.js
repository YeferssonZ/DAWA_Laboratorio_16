const Song = require('../models/Song');

const uploadSong = async (req, res) => {
  try {
    const { title, artist } = req.body;
    const audioFile = req.files['audio'][0];
    const logoFile = req.files['logo'][0];

    const song = new Song({
      title: title,
      artist: artist,
      audioUrl: audioFile.path,
      logoUrl: logoFile.path,
    });

    const savedSong = await song.save();
    res.status(201).json(savedSong);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const getAllSongs = async (req, res) => {
  try {
    const songs = await Song.find();
    res.status(200).json(songs);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const getSongById = async (req, res) => {
  try {
    const { songId } = req.params;
    const song = await Song.findById(songId);
    
    if (!song) {
      return res.status(404).json({ error: 'Song not found' });
    }

    res.status(200).json(song);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const updateSong = async (req, res) => {
  try {
    const { songId } = req.params;
    const { title, artist } = req.body;

    const updatedSong = await Song.findByIdAndUpdate(
      songId,
      { title, artist },
      { new: true }
    );

    if (!updatedSong) {
      return res.status(404).json({ error: 'Song not found' });
    }

    res.status(200).json(updatedSong);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const deleteSong = async (req, res) => {
  try {
    const { songId } = req.params;

    const deletedSong = await Song.findByIdAndDelete(songId);

    if (!deletedSong) {
      return res.status(404).json({ error: 'Song not found' });
    }

    res.status(200).json(deletedSong);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

module.exports = {
  uploadSong,
  getAllSongs,
  getSongById,
  updateSong,
  deleteSong,
};
