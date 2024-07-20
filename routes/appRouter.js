import express from "express";
import validator from "validator";
import bcrypt from "bcrypt";
import db from "../utils/db.js";
import jwt from "jsonwebtoken";
import "dotenv/config";
import cookieParser from "cookie-parser";
import checkAuth from "../middlewares/checkAuth.js";

const router = express.Router();

router.use(express.urlencoded({ extended: true }));
router.use(cookieParser());

router.get("/", (req, res) => {
  res.render("layout", { page: "home", pageTitle: " homepage" });
});

router.get("/registrazione", (req, res) => {
  res.render("layout", {
    page: "registrazione",
    pageTitle: " registrazione",
    msg: "",
    valori: { nome: "", email: "", username: "" },
  });
});

router.post("/registrazione", async (req, res) => {
  const { nome, email, username, password } = req.body;
  let error = false;
  if (
    !validator.isAlpha(nome) ||
    !validator.isLength(nome, { min: 2, max: 50 })
  ) {
    error = true;
  }
  if (!validator.isEmail(email)) {
    error = true;
  }
  if (
    !validator.isAlphanumeric(nome) ||
    !validator.isLength(username, { min: 6, max: 50 })
  ) {
    error = true;
  }
  if (!validator.isStrongPassword(password)) {
    error = true;
  }
  if (error) {
    return res.render("layout", {
      page: "registrazione",
      pageTitle: "registrazione",
      msg: "controlla la correttezza dei campi",
      valori: { nome, email, username },
    });
  }
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  const users = { nome, email, username, password: hash };
  const ris = await db.users.insertOne(users);
  console.log(ris);
  res.redirect("/login");
});

router.get("/logout", (req, res) => {
  const cookieSetting = {
    expires: new Date(0),
    httpOnly: true,
    secure: false,
  };
  res.cookie("tokenJWT", "", cookieSetting).send("logout effettuato");
});

router.get("/login", (req, res) => {
  res.render("layout", { page: "login", pageTitle: " login" });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await db.users.findOne({ username });

  if (user) {
    const passwordCheck = bcrypt.compareSync(password, user.password);
    if (passwordCheck) {
      const payload = { sub: user._id.toString(), isLogged: true };
      const token = jwt.sign(payload, process.env.JWT_KEY, { expiresIn: 60 });
      res.cookie("tokenJWT", token, {
        maxAge: 60 * 1000,
        httpOnly: true,
        secure: false,
      });
      return res.redirect("/user/dashboard");
    }
    res.redirect("/login");
  }

  res.send("controllo correttezza dati di login");
});

router.get("/user/dashboard", checkAuth, (req, res) => {
  res.render("layout", {
    page: "user-dashboard",
    pageTitle: " user dashboard",
  });
});

router.get("/user/profile", checkAuth, (req, res) => {
  res.send("pagina di profilo");
});

export default router;
