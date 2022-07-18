const mongoose = require('mongoose');
const characterService = require('./character.service');

const findAllCharactersController = async (req, res) => {
  const allCharacters = await characterService.findAllCharactersServive();

  if (!allCharacters.lenght === 0) {
    return res.status(404).send({ message: 'Nenhuma character cadastrado!' });
  }

  res.send(allCharacters);
};

const findByIdCharacterController = async (req, res) => {
  const idParams = req.params.id;
  const oneCharacter = await characterService.findByIdCharacterService(
    idParams,
  );

  if (!oneCharacter) {
    return res.status(404).send({ message: 'Character não encontrado!' });
  }

  res.send(oneCharacter);
};

const createCharacterController = async (req, res) => {
  const character = req.body;
  const newCharacter = await characterService.createCharacterService(character);
  res
    .status(201)
    .send({ message: 'Character criado com sucesso!', newCharacter });
};

const updateCharacterController = async (req, res) => {
  const idParams = req.params.id;
  const editCharacter = req.body;
  const updateCharacter = await characterService.updateCharacterService(
    idParams,
    editCharacter,
  );
  res.send({ message: 'Character atualizado com sucesso!', updateCharacter });
};

const deleteCharacterController = async (req, res) => {
  const idParams = req.params.id;
  await characterService.deleteCharacterService(idParams);
  res.send({ message: 'Character deletado com sucesso!' });
};

const searchCharactersByNameController = async (req, res) => {
  try {
    const { name } = req.query;

    const chosenCharacters =
      await characterService.searchCharactersByNameService(name);

    if (chosenCharacters === 0) {
      return res.status(404).send({ message: 'not found' });
    }

    res.send({
      characters: chosenCharacters.map((character) => ({
        id: character._id,
        name: character.name,
        image: character.imagem,
        user: character.user,
      })),
    });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

module.exports = {
  findAllCharactersController,
  findByIdCharacterController,
  createCharacterController,
  updateCharacterController,
  deleteCharacterController,
  searchCharactersByNameController,
};
