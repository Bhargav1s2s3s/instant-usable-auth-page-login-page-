import express, { urlencoded } from "express";
import path from "path";
import mongoose from "mongoose";
import dotenv from "dotenv";
import rout from "./controllers/routes.js";
import session from "express-session";

dotenv.config();
const app = express();
app.use(express.json());

app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));
app.use(express.urlencoded({ extended: true }));

mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("Database Connected"))
  .catch((err) => console.log("Failed to Connect", err));

app.use(
  session({
    secret: "otpSecret",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 5 * 60 * 1000 }, // Optional: 5-min expiry
  })
);

app.use("/api", rout);

const port = process.env.PORT || 8080;
app.listen(port, (err) => {
  if (!err) {
    console.log(`Server running on port ${port}`);
  } else {
    console.log("server failed", err);
  }
});
