import mongoose from "mongoose";

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  context: { type: String },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
});

export default mongoose.model("OTP", otpSchema);
