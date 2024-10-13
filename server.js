require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const db = require("better-sqlite3")("ourApp.db");
db.pragma("journal_mode = WAL");
const app = express();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

//database setup starts here

const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username STRING NOT NULL UNIQUE,
            password STRING NOT NULL
        );
        `).run()
})
createTables();
//database setup ends here

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: false}));
app.use(express.static("public"));
app.use(cookieParser());

app.use(function (req, res, next){
    res.locals.errors = [];

    //try to decode the incoming cookie
    try{
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
        req.user = decoded
    }catch(err){
        req.user = false;
    }

    res.locals.user = req.user;
    console.log(req.user);

    next();
})

app.get('/', (req, res) => {
    if(req.user){
        return res.render("dashboard");
    }
    res.render("homepage");
});

app.get('/login', (req, res) => {
    res.render("login");
})

app.get('/logout', (req, res) => {
    res.clearCookie("ourSimpleApp");
    res.redirect('/');
});

app.post('/login', (req, res) => {
    let errors = [];
    if(typeof req.body.username !== "string"){
        req.body.username = "";
    }
    if(typeof req.body.password !== "string"){
        req.body.password = "";
    }

    if(req.body.username.trim() === "" || req.body.password === ""){
        errors = ["Invalid username/password"];
    }

    if(errors.length){
        return res.render('login', {errors});
    }
    
    const userInQuestionStatement = db.prepare("SELECT * from users where username = ?");
    const userInQuestion = userInQuestionStatement.get(req.body.username);

    if(!userInQuestion){
        errors = ["Invalid username/password"];
        return res.render("login", {errors});
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password);
    if(!matchOrNot){
        errors = ["Invalid username/password"];
        return res.render("login", {errors});
    }

    // give them a cookie and redirect
    const ourTokenValue = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
        skyColor: "blue",
        userId: userInQuestion.id,
        userName: userInQuestion.username
    }, process.env.JWTSECRET);

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    });

    res.redirect("/");

});

app.post('/register', (req, res) => {
    const errors = [];

    if(typeof req.body.username !== "string"){
        req.body.username = "";
    }
    if(typeof req.body.password !== "string"){
        req.body.password = "";
    }

    req.body.username = req.body.username.trim();

    if(!req.body.username){
        errors.push("You must provide a username");
    }
    if(req.body.username && req.body.username.length < 3){
        errors.push("Username cannot be less than 3 characters");
    }
    if(req.body.username && req.body.username.length > 10){
        errors.push("Username cannot be more than 10 characters");
    }
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)){
        errors.push("Username can only contains letters and numbers");
    }

    //check if username exists already
    const usernameStatement = db.prepare("SELECT * from users WHERE username = ?");
    const usernameCheck = usernameStatement.get(req.body.username);
    if(usernameCheck){
        errors.push("Username is already taken");
    }

    if(!req.body.password){
        errors.push("You must provide a Password");
    }
    if(req.body.password && req.body.password.length < 8){
        errors.push("Password cannot be less than 8 characters");
    }
    if(req.body.password && req.body.password.length > 18){
        errors.push("Password cannot be more than 18 characters");
    }

    if(errors.length){
        return res.render("homepage", {errors});
    }

    //Save the new user into a database
    const salt = bcrypt.genSaltSync(10);
    req.body.password = bcrypt.hashSync(req.body.password, salt);

    const ourStatement = db.prepare(`
            INSERT into users (username, password) VALUES (?, ?)
        `);
    const result = ourStatement.run(req.body.username, req.body.password);

    const lookupStatement = db.prepare("SELECT * from users where ROWID = ?");
    const ourUser = lookupStatement.get(result.lastInsertRowid);

    //log the user in by giving them a cookie
    const ourTokenValue = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
        skyColor: "blue",
        userId: ourUser.id,
        userName: ourUser.username
    }, process.env.JWTSECRET);

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    });

    res.redirect("/");
});

app.listen(3000);