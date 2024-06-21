const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");

require("../../passport.js");

const User = require("../../models/user");
const checkAuth = require("../../middleware/checkAuth.js");
const AuthController = require("../../controller/authController.js");
const { STATUS_CODES } = require("../../utils/statusCodes.js");
const FileController = require("../../controller/fileController.js");
const sendEmailWithSendGrid = require("../../utils/sendEmail.js");

const Joi = require("joi");
const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const emailSchema = Joi.object({
  email: Joi.string().email().required(),
});

/* POST localhost:3000/api/users/signup */
router.post("/signup", async (req, res) => {
  try {
    const { error, value } = userSchema.validate(req.body);
    if (error) {
      return res
        .status(STATUS_CODES.badRequest)
        .json({ message: error.details[0].message });
    }

    const { email, password } = value;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res
        .status(STATUS_CODES.conflict)
        .json({ message: "Email in use" });
    }

    const newUser = await AuthController.signup({ email, password });
    res.status(STATUS_CODES.created).json({
      user: {
        email: newUser.email,
        subscription: newUser.subscription,
      },
    });
  } catch (error) {
    res
      .status(STATUS_CODES.error)
      .json({ message: `Server error: ${error.message}` });
  }
});

/* POST localhost:3000/api/users/login */
router.post("/login", async (req, res, next) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res
        .status(STATUS_CODES.badRequest)
        .json({ message: error.details[0].message });
    }

    const { email, password } = value;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(STATUS_CODES.unauthorized).json({
        message: "Email or password is wrong",
      });
    }

    const token = await AuthController.login({ email, password });

    res.status(STATUS_CODES.success).json({
      token: token,
      user: {
        email: user.email,
        subscription: user.subscription,
      },
    });
  } catch (error) {
    res
      .status(STATUS_CODES.error)
      .json({ message: `Server error: ${error.message}` });
  }
});

/* GET localhost:3000/api/users/logout */
router.get("/logout", checkAuth, async (req, res, next) => {
  try {
    const header = req.get("authorization");
    if (!header) {
      return res
        .status(STATUS_CODES.unauthorized)
        .json({ message: "Authentication is required for this route" });
    }

    const token = header.split(" ")[1];
    const payload = AuthController.getPayloadFromJWT(token);

    const filter = { _id: payload.data._id };

    const user = await User.findOne(filter);
    if (!user) {
      return res
        .status(STATUS_CODES.unauthorized)
        .json({ message: "Not authorized" });
    }

    await User.findOneAndUpdate(filter, { token: null });

    res.status(STATUS_CODES.noContent).send();
  } catch (error) {
    respondWithError(res, error, STATUS_CODES.error);
  }
});

/* GET localhost:3000/api/users/current */
router.get("/current", checkAuth, async (req, res, next) => {
  try {
    const header = req.get("authorization");
    if (!header) {
      return res
        .status(STATUS_CODES.unauthorized)
        .json({ message: "Authentication is required for this route" });
    }

    const token = header.split(" ")[1];
    const payload = AuthController.getPayloadFromJWT(token);

    const filter = { _id: payload.data._id };

    const user = await User.findOne(filter);
    if (!user) {
      return res
        .status(STATUS_CODES.unauthorized)
        .json({ message: "Not authorized" });
    }

    res.status(STATUS_CODES.success).json({
      email: user.email,
      subscription: user.subscription,
    });
  } catch (error) {
    respondWithError(res, error, STATUS_CODES.error);
  }
});

/* PATCH localhost:3000/api/users/avatars */
router.patch(
  "/avatars",
  [checkAuth, FileController.uploadFile],
  async (req, res, next) => {
    try {
      const response = await FileController.processAvatar(req, res);
      res.status(STATUS_CODES.success).json(response);
    } catch (error) {
      res
        .status(STATUS_CODES.unauthorized)
        .json({ message: "Not authorized", error: error });
    }
  }
);

/* GET  localhost:3000/api/users/verify/:verificationToken */
router.get("/verify/:verificationToken", async (req, res) => {
  try {
    const { verificationToken } = req.params;

    const user = await User.findOne({ verificationToken });

    if (!user) {
      return res
        .status(STATUS_CODES.notFound)
        .json({ message: "User not found" });
    }

    await User.findOneAndUpdate(
      { verificationToken: verificationToken },
      { verificationToken: "", verify: true }
    );

    res
      .status(STATUS_CODES.success)
      .json({ message: "Verification successful" });
  } catch (error) {
    respondWithError(res, error, STATUS_CODES.error);
  }
});

// POST localhost:3000/api/users/verify/
router.post("/verify", async (req, res) => {
  try {
    const isEmail = req.body?.email;
    if (!isEmail) {
      throw new Error("missing required field email");
    }

    const { error, value } = emailSchema.validate(req.body);
    if (error) {
      return res
        .status(STATUS_CODES.badRequest)
        .json({ message: error.details[0].message });
    }
    const { email } = value;
    const user = await User.findOne({ email });
    if (!user) {
      throw new Error("The email is incorrect");
    }
    if (user.verify) {
      return res
        .status(STATUS_CODES.badRequest)
        .json({ message: "Verification has already been passed" });
    }

    sendEmailWithSendGrid(email, user.verificationToken, 2);

    res.status(STATUS_CODES.success).json({
      message: "Verification email sent",
    });
  } catch (error) {
    respondWithError(res, error, STATUS_CODES.error);
  }
});

/**
 * Handles Error Cases
 */
function respondWithError(res, error, statusCode) {
  console.error(error);
  res.status(statusCode).json({ message: `${error}` });
}

module.exports = router;
