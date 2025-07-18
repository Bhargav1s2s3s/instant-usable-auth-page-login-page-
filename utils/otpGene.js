export function generateOTP(length = 6) {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// export function generateOTP() {
//   let otp;
//   let str = "1234567890";

//   for (let i = 0; i < 6; i++) {
//     otp += str.charAt(Math.floor(Math.random() * str.length));
//   }
//   return otp;
// }
