const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
// const sendgridTransport = require("nodemailer-sendgrid-transport");

const User = require("../models/user");
const Token = require("../models/token");

const transporter = nodemailer.createTransport(
  //cau hinh ndemailer su dng sendrid
  // sendgridTransport({
  //   auth: {
  //     api_key:
  //       "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",
  //   },
  // })
  {
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "0a669dd93a4cc4",
      pass: "3160ac70c0038a",
    },
  }
);

exports.getLogin = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message,
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message,
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  console.log("email", email);
  console.log("pass", password);
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        req.flash(
          "error",
          `The email address ${email} + ' is not associated with any account. please check and try again!`
        );
        return res.redirect("/login");
      }
      // check user is verified or not
      if (!user.isVerified) {
        return req.flash(
          "error",
          "Your Email has not been verified. Please click on resend"
        );
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect("/");
            });
          }
          req.flash("error", "Invalid email or password.");
          res.redirect("/login");
        })
        .catch((err) => {
          console.log(err);
          res.redirect("/login");
        });
    })
    .catch((err) => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  User.findOne({ email: email })
    .then((userDoc) => {
      if (userDoc) {
        req.flash(
          "error",
          "E-Mail exists already, please pick a different one."
        );
        return res.redirect("/signup");
      }
      return bcrypt.hash(password, 12).then((hashedPassword) => {
        const user = new User({
          email: email,
          password: hashedPassword,
          cart: { items: [] },
        });
        return user.save(function (err) {
          // generate token and save
          var token = new Token({
            _userId: user._id,
            token: crypto.randomBytes(16).toString("hex"),
          });
          // Send email (use credintials of SendGrid)
          var mailOptions = {
            from: "testktrdh@gmail.com",
            to: email,
            subject: "Account Verification Link",
            text:
              "Hello user" +
              ",\n\n" +
              "Please verify your account by clicking the link: \nhttp://" +
              req.headers.host +
              "/confirmation/" +
              user.email +
              "/" +
              token.token +
              "\n\nThank You!\n",
          };
          token.save();
          transporter.sendMail(mailOptions, function (err) {
            console.log("mail options", mailOptions);
            if (err) {
              return res.status(500).send({
                msg: "Technical Issue!, Please click on resend for verify your Email.",
              });
            }
            return res
              .status(200)
              .send(
                "A verification email has been sent to " +
                  user.email +
                  ". It will be expire after one day. If you not get verification Email click on resend token."
              );
          });
        });
      });
    })
    .catch((err) => {
      console.log(err);
    });
};

// It is GET method, you have to write like that
//    app.get('/confirmation/:email/:token',confirmEmail)

exports.confirmEmail = function (req, res, next) {
  console.log("1");
  Token.findOne({ token: req.params.token }, function (err, token) {
    // token is not found into database i.e. token may have expired
    if (!token) {
      return res.status(400).send({
        msg: "Your verification link may have expired. Please click on resend for verify your Email.",
      });
    }
    // if token is found then check valid user
    else {
      User.findOne(
        { _id: token._userId, email: req.params.email },
        function (err, user) {
          // not valid user
          if (!user) {
            return req.flash(
              "error",
              "We were unable to find a user for this verification. Please SignUp!"
            );
          }
          // user is already verified
          else if (user.isVerified) {
            // return res
            //   .status(200)
            //   .send("User has been already verified. Please Login");
            return res.redirect("/login");
          }
          // verify user
          else {
            // change isVerified to true
            user.isVerified = true;
            user.save(function (err) {
              // error occur
              if (err) {
                return req.flash("error", "ERR!");
              }
              // account successfully verified
              else {
                return res.redirect("/login");
              }
            });
          }
        }
      );
    }
  });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect("/");
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message,
  });
};
