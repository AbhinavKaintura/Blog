
import express  from "express";
import bodyParser from "body-parser";
import { dirname } from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const port = 3002;
const app = express();
const __dirname = dirname(fileURLToPath(import.meta.url));
const saltRounds = 10;
env.config();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
//app.use(express.static('css'));
//app.set('view engine', 'ejs');
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

app.get("/" , (req, res ) => {
    res.render(__dirname + "/views/home.ejs");
});

app.get("/login" , (req, res) => {
    res.render(__dirname + "/views/login.ejs");
});

app.get("/register", (req, res) => {
    res.render(__dirname + "/views/register.ejs");
});

app.post("/check" , (req , res) => {
    res.render(__dirname + "/views/createblog.ejs");
});

app.post("/lifeshort" , (req , res) =>{
    res.render(__dirname + "/views/lifeisshort.ejs");
});

app.post("/ageessay" , (req, res) => {
    res.render(__dirname + "/views/ageofessay.ejs");
});

app.post("/kids" , (req, res) => {
    res.render(__dirname + "/views/havekids.ejs");
});

app.get("/logout", (req,res) => {
    req.logout(function (err) {
        if(err) {
            return next(err);
        }
        res.render("/");
    })
})

app.get("/myblog", async (req, res) => {
    console.log(req.user);

    if(req.isAuthenticated()) {
        try {
            const result = await db.query(`SELECT blog FROM users WHERE email = $1`, [req.user.email]);
            console.log(result);
            const blog = result.rows[0].blog;
            if(blog) {
                res.render("myblog.ejs", { blog: blog});
            } else {
                res.render("myblog.ejs", { blog: "Enter your blog. "});
            }
        } catch (err) {

        }
    } else {
        res.redirect("/login")
    }
} )

app.get("/submit", function (req, res) {
    if(req.isAuthenticated()) {
        res.render("submit.ejs");
    } else {
        res.redirect("/login.ejs");
    }
})

app.get(
    "/auth/google", 
    passport.authenticate("google", {
      scope: ["profile", "email"],
    })
  );
  
  app.get(
    "/auth/google/secrets", 
    passport.authenticate("google", {
      successRedirect: "/myblog",
      failureRedirect: "/login",
    })
  );

app.post("/login", passport.authenticate("local", {
    successRedirect: "/myblog",
    failureRedirect: "/login",
}));

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
    try {

        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if(checkResult.rows.length > 0) {
            res.redirect("/login");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if(err) {
                    console.log("error while hashing password : ", err);
                } else {
                    const result = await db.query("INSERT INTO users(email, password) VALUES ($1, $2) RETURNING *",[email, hash]);
                    const user = result.rows[0];
                    req.login(user, (err) => {
                        console.log("success");
                        res.redirect("/myblog");
                    })
                }
            })
        }
    } catch (err) {
        console.log(err);
    }
})

app.post("/submit", async function (req, res) {
    const submittedBlog = req.body.blog;
    console.log(req.user);
    try {
        await db.query(`UPDATE users SET blog = $1 WHERE email = $2`, [submittedBlog, req.user.email,])
        res.redirect("/myblog");
    } catch (err) {
        console.log(err);
    }
})


passport.use("local", new Strategy(async function verify(username, password, cb) {
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);

        if(result.rows.length > 0) {
            const user = result.rows[0];
            const storedHashedPassword = user.password;
            bcrypt.compare(password, storedHashedPassword, (err, valid) => {
                if (err) {
                    console.log("error comparing passwords ", err);
                    return cb(err);
                } else {
                    if(valid) {
                        return cb(null, user);
                    }
                    else {
                        return cb(null, false);
                    }
                }
            })
        } else {
            return cb("User not found.");
        }
    } catch (err) {
        console.log(err);
    }
}));

passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret : process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async(accessToken, refreshToken, profile, cb) => {
        try {
            const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email,]);
            if(result.rows.length === 0 ){
                const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [profile.email, "google"]);
                return cb(null, newUser.rows[0]);
            } else {
                return cb(null, result.rows[0]);
            }
        } catch {
            return cb(err);
        }
    }
));

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
 