require("dotenv").config();
const express = require("express");
const fs = require("fs");
const app = express();
const port = process.env.PORT || 3000;
const Mail = require("./email.js");
const path = require("path");
const ejs = require("ejs");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const { json } = require("stream/consumers");
const otpgenerator = require("./generateOTP.js");
const session = require("express-session");
const { generateAccessToken, verifyToken } = require("./jwt.js");

app.set("view engine", "ejs");
app.set("views", path.resolve("./views"));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

let db = [];

const setUserSession = (req, res, next) => {
  const { email, name } = req.user;
  res.cookie("isLoggedIn", "true");
  res.cookie("userEmail", email);
  res.cookie("userName", name);
  next();
};

const gererateOTP = () => {
  return crypto.randomInt(100000, 999999);
};

const render_Email_Template = async (data) => {
  console.log(data);
  try {
    const templatePath = path.join(__dirname, "views", "test.ejs");
    const template = fs.readFileSync(templatePath, "utf-8");
    return ejs.render(template, { data });
  } catch (err) {
    console.error("Error rendering email template:", err);
  }
};

app.get("/get", (req, res) => {
  res.send("get");
});

app.get("/", (req, res) => {
  let cookies = req.cookies["isLoggedIn"]
    ? JSON.parse(req.cookies["isLoggedIn"])
    : null;
  let username = req.cookies["username"];
  if (!cookies) {
    res.redirect("/login");
  }
  res.render("./index", { user_name: username });
});

app.get("/login", (req, res) => {
  res.render("./login.ejs");
});

app.post("/login", (req, res) => {
  let { email, password } = req.body;
  let user = db.find(
    (user) => user.email === email && user.password === password
  );
  if (user) {
    console.log("user found", user);
    req.cookies("isLoggedIn", "true");
    return res.redirect("/");
  } else {
    console.log("User not Found");
    return res.status(404).send("invalid credencial");
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("isLoggedIn");
  res.redirect("/login");
});

app.get("/forgot-password", (req, res) => {
  res.render("./forget-password");
});

app.post("/forgot-password", (req, res) => {
  let { email } = req.body;
  if (email && db.find((user) => user.email === email)) {
    let otp = gererateOTP();
    otpgenerator.set(email, otp);
    req.session.email = email;
    req.session.otp = otp;
    res.redirect("/renderEmailTemplate");
  } else {
    res.status(400).send("invalid email");
  }
});

app.post("/verify-otp", (req, res) => {
  let { email, otp } = req.body;
  let verify = otpgenerator.verify(email, otp);
  if (verify) {
    console.log("verified");
    res.cookie("isLoggedIn", "true");
    res.redirect("/");
  } else {
    console.log("invalid OTP");
    res.redirect("/get");
  }
});

app.get("/signup", (req, res) => {
  res.render("./signup");
});

app.post("/signup", (req, res) => {
  let { name, email, password } = req.body;
  db.push({ name, email, password, isVerified: true });
  let id = generateAccessToken({ name, email });
  let mail = new Mail();
  mail.setTo(email);
  mail.setSubject("Email verification");
  mail.sethtml(
    `<a href="http://localhost:${port}/verify/${id}">Click here to verify your email</a>`
  );
  mail
    .send()
    .then((result) => {
      res.render("./verifyemailloading");
    })
    .catch((error) => {
      console.log(error);
      res.status(500).send("Internal server Error");
    });
});

app.get(
  "/verify/:id",
  (req, res, next) => {
    const { id } = req.params;
    let isVerified = verifyToken(id);
    if (isVerified?.status) {
      db = db.map((user) => {
        if (user.email === isVerified?.payload?.email) {
          user.isVerified = true;
          req.user = { email: user.email, name: user.name };
        }
        return user;
      });
      next();
    } else {
      res.redirect("/login");
    }
  },
  setUserSession,
  (req, res) => {
    res.redirect("/");
  }
);

app.get("/renderEmailTemplate", async (req, res) => {
  try {
    let { email, otp } = req.session;
    const htmlContent = await render_Email_Template({ email, otp });

    const mail = new Mail();
    mail.setTo(email);
    mail.setSubject("password Reset");
    mail.sethtml(htmlContent);
    mail
      .send()
      .then(() => {
        res.render("verify-otp", { email: email });
      })
      .catch((error) => {
        console.log(error);
        res.status(404).send("Internal Server Error");
      });
  } catch (error) {
    console.log(error);
  }
});

app.listen(port, (req, res) => {
  console.log(`app is listen on port ${port}`);
});
