const { Schema, model } = require("mongoose");

const userSchema = new Schema({
  username: {
    type: String,
    unique: true
  },
  password: {
    type: String,
    required: [true, 'Password is required.']
  }
});

const User = model("User", userSchema);

module.exports = User;
