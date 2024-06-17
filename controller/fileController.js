const multer = require("multer");
const Jimp = require("jimp");
const fs = require("fs").promises;
const path = require("path");
const User = require("../models/user.js");

const storage = multer.diskStorage({
  destination: "/tmp/",
  filename: function (_req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix);
  },
});
const uploadFile = multer({ storage: storage }).single("avatar");

async function processAvatar(req, res) {
  const userId = req.user.id;

  try {
    if (!req.file) {
      throw new Error("No file uploaded");
    }

    const avatar = await Jimp.read(req.file.path);
    await avatar.resize(250, 250).quality(80).write(req.file.path);

    const newFilename = `${userId}_${Date.now()}${path.extname(
      req.file.originalname
    )}`;
    const newPath = path.normalize(path.join("public", "avatars", newFilename));
    await fs.rename(req.file.path, newPath);

    await User.findByIdAndUpdate(userId, { avatarURL: newPath });

    const result = {
      avatarUrl: newPath,
    };

    return result;
  } catch (error) {
    throw new Error(`${error}`);
  }
}

module.exports = {
  uploadFile,
  processAvatar,
};
