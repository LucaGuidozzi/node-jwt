import express from "express";
import { MongoClient } from "mongodb";
import appRouter from "./routes/appRouter.js";
import db from "./utils/db.js";

const port = process.env.NODE_ENV || 3000;
const app = express();
const mongoClient = new MongoClient("mongodb://127.0.0.1:27017");

app.set("view engine", "ejs");
app.use(appRouter);

const connect = async () => {
  await mongoClient.connect();
  db.blog = mongoClient.db("blog");
  db.users = db.blog.collection("users");

  console.log("connessione a mongoDB avvenuta");
  app.listen(port, () =>
    console.log("server in ascolto di richieste in ingresso")
  );
};

connect().catch((err) => console.log(err));
