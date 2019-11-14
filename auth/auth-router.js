const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Users = require('../users/users-model.js');
const { validateUser } = require('../users/users-helper.js');


// '/api/auth' ENDPOINTS: 

router.post('/register', (req, res) => {
  let user = req.body;
  const validateResults = validateUser(user);

  if(validateResults.isSuccessful === true){
    const hash = bcrypt.hashSync(user.password, 10); 
    user.password = hash;

    Users.add(user)
      .then(saved => {
        res.status(201).json(saved);
      })
      .catch(error => {
        res.status(500).json(error);
    });
  } else {
    res.status(400).json({message:'Error:', err: validateResults.errors})
  }
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        //produce token (everything in token is VISIBLE)
        const token = getJwtToken(user.username);

        //send token to client
        res.status(200).json({
          message: `Greetings, Master ${user.username}.`,
          token,
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function getJwtToken(username){
  const payload = {
    username,
  };

  const secret = process.env.JWT_SECRET || 'Hush Puppies';

  const options = {
    expiresIn: '1d'
  };

  return jwt.sign(payload, secret, options);
}

module.exports = router;