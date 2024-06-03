const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const passport = require("passport");
require("../passport.js");
const User = require("../models/user");

dotenv.config();
const secret = process.env.TOKEN_SECRET;

async function signup(data) {
  const saltRounds = 10;
  const encryptedPassword = await bcrypt.hash(data.password, saltRounds);

  const newUser = new User({
    email: data.email,
    password: encryptedPassword,
  });

  return User.create(newUser);
}

async function login(data) {
  const { email, password } = data;

  const user = await User.findOne({ email });

  const isMatching = await bcrypt.compare(password, user.password);

  if (isMatching) {
    const token = jwt.sign(
      {
        data: user,
      },
      secret,
      { expiresIn: "1h" }
    );

    await User.findOneAndUpdate({ email: email }, { token: token });

    return token;
  } else {
    throw new Error("Email or password is wrong");
  }
}

function getPayloadFromJWT(token) {
  try {
    const payload = jwt.verify(token, secret);
    return payload;
  } catch (err) {
    console.error(err);
  }
}

module.exports = {
  signup,
  login,
  getPayloadFromJWT,
};
