import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcrypt"

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/auth";
mongoose.connect(mongoUrl);
mongoose.Promise = Promise;

const { Schema, model } = mongoose;

const userSchema = new Schema({
  name: {
    type: String,
    unique: true
  },
  email: {
    type: String,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString("hex")
  }
});

const User = model("User", userSchema);

const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({ accessToken: req.header("Authorization") });
  if (user) {
    req.user = user;
    next();
  } else {
    res.status(401).json({ loggedOut: true });
  }
};

// Defines the port the app will run on. Defaults to 8080, but can be overridden
// when starting the server. Example command to overwrite PORT env variable value:
// PORT=9000 npm start
const port = process.env.PORT || 8080;
const app = express();

// Add middlewares to enable cors and json body parsing
app.use(cors());
app.use(express.json());

// Start defining your routes here
app.get("/", (req, res) => {
  res.send("Hello Technigo!");
});

app.post("/users", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const salt = bcrypt.genSaltSync(); // Generera salt (cost factor: förmodligen 10, brukar vara standard inställning om inget anges)
    //const salt = bcrypt.genSaltSync(10); // Generera salt (cost factor: 10)
    const hashedPassword = bcrypt.hashSync(password, salt); // Hasha lösenordet med saltet

    const user = new User({ name, email, password: hashedPassword });

    user.save();
    res.status(201).json({ id: user._id, accessToken: user.accessToken });
  } catch (err) {
    res.status(400).json({ message: "could not create user", errors: err.errors });
  }
});

app.get("/secrets", authenticateUser);
app.get("/secrets", (req, res) => {
  res.json({ secret: "This is a super secret message." })
});
// Problem:
// Eftersom båda routes använder samma endpoint (/secrets), kommer den andra route-definitionen att skriva över den första. Det betyder att authenticateUser-middleware aldrig kommer att anropas, vilket innebär att alla användare kan få tillgång till det hemliga meddelandet utan autentisering.
// Lösning:
// app.get("/secrets", authenticateUser, (req, res) => {
//  res.json({ secret: "This is a super secret message." });
// });


// For the user to be able to log in
app.post("/sessions", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    res.json({ userId: user._id, accessToken: user.accessToken });
  } else {
    res.json({ notFound: true });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
