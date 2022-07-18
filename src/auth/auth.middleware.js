require('dotenv').config();
const jwt = require('jsonwebtoken');
const { findByIdUserService } = require('../users/users.service');

module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ message: 'Token Não Informado!' });
  }

  const parts = authHeader.split(' ');

  if (parts.length !== 2) {
    return res.status(401).send({ message: 'Token Inválido!' });
  }

  const [scheme, token] = parts;

  if (!/^Bearer$/i.test(scheme)) {
    return res.status(401).send({ message: 'Token Mal Formatado!' });
  }

  jwt.verify(token, process.env.SECRET, async (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'Token Inválido!' });
    }
    const user = await findByIdUserService(decoded.id);

    req.userId = user.id;
    return next();
  });
};
