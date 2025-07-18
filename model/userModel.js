import mongoose from "mongoose";
import { type } from "os";

const userScheme = new mongoose.Schema({
  firstname: String,
  lastname: String,
  email: { type: String, require: true, unique: true },
  password: { type: String, require: true },
});

export default mongoose.model("user", userScheme);
