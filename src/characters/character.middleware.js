const mongoose = require('mongoose');

const validId = (req, res, next) => {
  const idParams = req.params.id;
  if (!mongoose.Types.ObjectId.isValid(idParams)) {
    res.status(400).send({ message: 'Id inválido!' });
  }
  next();
};

const validObjectBody = (req, res, next) => {
  const character = req.body;
  if (!character.user || !character.name || !character.imagem) {
    return res
      .status(400)
      .send({ message: 'Envie envie todos os campos do character!' });
  }
  next();
};

module.exports = {
  validId,
  validObjectBody,
};
