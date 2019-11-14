const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    const secret = process.env.JWT_SECRET || 'Hush Puppies';
    jwt.verify(token, secret, (err, decodedToken)=> {
      if(err){
        res.status(401).json({message: 'Bad token'})
      } else {
        req.decodedJwt = decodedToken;
        next()
      }
    });
  } else {
    res.status(400).json({ message: 'No credentials provided' });
  }
};