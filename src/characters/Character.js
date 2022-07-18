const mongoose = require('mongoose');

const CharacterSchema = new mongoose.Schema({
  user: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  imagem: {
    type: String,
    required: true,
  },
});

const Character = mongoose.model('characters', CharacterSchema);
module.exports = Character;
