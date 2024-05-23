const mongoose = require("mongoose");

async function connectToDb() {
  try {
    await mongoose.connect(
      "mongodb+srv://moldovanmms:JFWpGJMMCFL7E8Wb@cluster0.ncgfkyy.mongodb.net/db-contacts"
    );
    console.log("Database connection successful");
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

module.exports = connectToDb;
