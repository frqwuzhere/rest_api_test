const express = require("express");
const bcrypt = require("bcryptjs");
const validator = require("validator");
const router = express.Router();
const { nanoid } = require("nanoid");

const users = require("./user"); //database user sementara

router.post("/register", (req, res) => {
  const { email, username, password } = req.body;

  const isEmailValid = validator.isEmail(email);
  if (!isEmailValid) {
    return res.status(404).send({ message: "Email is invalid" });
  }

  const emailExists = users.some((u) => u.email === email);
  if (emailExists) {
    return res.status(400).send({ message: "Email already registered." });
  }

  const userExists = users.some((u) => u.username === username);
  if (userExists) {
    return res.status(400).send({ message: "User already exists" });
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  const isPasswordValid = passwordRegex.test(password);
  if (!isPasswordValid) {
    return res.status(400).send({
      message: "Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character",
    });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  const newUser = {
    id: nanoid(),
    email,
    username,
    password: hashedPassword,
  };

  users.push(newUser);

  res.status(201).send({ message: "User registered successfully" });
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).send({ message: "Invalid username or password" });
  }

  const passwordMatch = bcrypt.compareSync(password, user.password);
  if (!passwordMatch) {
    return res.status(401).send({ message: "Invalid username or password" });
  }

  res.status(201).send({ message: "Login succesfully" });
});

router.patch("/edit", (req, res) => {
  const { username, password, newUsername } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).send({ message: "Invalid username or password" });
  }

  const passwordMatch = bcrypt.compareSync(password, user.password);
  if (!passwordMatch) {
    return res.status(401).send({ message: "Invalid username or password" });
  }

  const newUser = users.find((u) => u.newUsername === username);
  if (!newUser) {
    return res.status(401).send({ message: "This username is already taken." });
  }

  user.username = newUsername;

  res.status(201).send({ message: "Successfully edit username" });
});

router.get("/list", (req, res) => {
  res.status(201).send(users);
});

module.exports = router;
