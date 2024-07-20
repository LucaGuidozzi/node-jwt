import jwt from "jsonwebtoken";

function checkAuth(req, res, next) {
  const tokenJWT = req.cookies.tokenJWT;
  if (!tokenJWT) return res.status(401).send("non sei autenticato!");
  try {
    const payload = jwt.verify(tokenJWT, process.env.JWT_KEY);
    next();
  } catch (err) {
    res.status(401).send("il token fornito non è valido ");
  }
}

export default checkAuth;
