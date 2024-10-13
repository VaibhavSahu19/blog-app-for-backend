require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const db = require("better-sqlite3")("ourApp.db");
db.pragma("journal_mode = WAL");
const app = express();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const sanitizeHTML = require("sanitize-html");
const marked = require('marked');


//database setup starts here

const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username STRING NOT NULL UNIQUE,
            password STRING NOT NULL
        );
    `).run();
    
    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            createdDate text,
            title STRING NOT NULL,
            body TEXT NOT NULL,
            authorid INTEGER,
            FOREIGN KEY (authorid) REFERENCES users(id)
        );
    `).run();
})
createTables();
//database setup ends here

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: false}));
app.use(express.static("public"));
app.use(cookieParser());

app.use(function (req, res, next){
    //make our markdown function availble
    res.locals.filterUserHTML = function(content){
        return sanitizeHTML(marked.parse(content), {
            allowedTags: ["p", "br", "ul", "li", "ol", "strong", "bold", "em", "i", "h1", "h2", "h3", "h4"],
            allowedAttributes: {}
        })
    }

    res.locals.errors = [];

    //try to decode the incoming cookie
    try{
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
        req.user = decoded
    }catch(err){
        req.user = false;
    }

    res.locals.user = req.user;
    next();
})

app.get('/', (req, res) => {
    if(req.user){
        const postsStatement = db.prepare(`SELECT * from posts where authorid = ? ORDER BY createdDate DESC`);
        const posts = postsStatement.all(req.user.userId);
        return res.render("dashboard", {posts});
    }
    res.render("homepage");
});

app.get('/no-post', (req, res) => {
    res.render("no-post");
})

app.get('/login', (req, res) => {
    res.render("login");
})

app.get('/logout', (req, res) => {
    res.clearCookie("ourSimpleApp");
    res.redirect('/');
});

function mustBeLoggedIn(req, res, next){
    if(req.user){
        return next();
    }
    return res.redirect("/");
}

app.get("/create-post", mustBeLoggedIn,  (req, res) => {
    res.render("create-post");
});

function sharedPostValidation(req){
    const errors = [];
    if(typeof req.body.title !== 'string'){
        req.body.title = "";
    }else if(typeof req.body.body !== 'string'){
        req.body.body = "";
    }

    //trim the html
    req.body.title = sanitizeHTML(req.body.title.trim(), {allowedTags: [], allowedAttributes: {}});
    req.body.body = sanitizeHTML(req.body.body.trim(), {allowedTags: [], allowedAttributes: {}});

    if(!req.body.title.trim() || !req.body.body.trim()){
        errors.push("You must provide a title/content for the post");
    }

    return errors;
}

app.get('/post/:id', (req, res) => {
    const statement = db.prepare(`SELECT posts.*, users.username from posts INNER JOIN users ON posts.authorid = users.id where posts.id = ?`);
    const post = statement.get(req.params.id);


    if(!post){
        return res.redirect('/');
    }

    const isAuthor = post.authorid === req.user.userId;

    res.render('single-post', {post, isAuthor});
});

app.get('/edit-post/:id', mustBeLoggedIn, (req, res) => {
    //try to look up to post in question
    const statement = db.prepare(`SELECT * from posts where id = ?`);
    const post = statement.get(req.params.id);

    //if post does not exits
    if(!post){
        return res.redirect('/no-post');
    }
    //if you are not the author re-direct to homepage
    if(post.authorid !== req.user.userId){
        return res.redirect('/');
    }

    
    //otherwise, render the edit post template
    res.render('edit-post', {post})
});

app.post('/edit-post/:id', mustBeLoggedIn, (req, res) => {
    //try to look up to post in question
    const statement = db.prepare(`SELECT * from posts where id = ?`);
    const post = statement.get(req.params.id);

    //if post does not exits
    if(!post){
        return res.redirect('/no-post');
    }
    //if you are not the author re-direct to homepage
    if(post.authorid !== req.user.userId){
        return res.redirect('/');
    };

    const errors = sharedPostValidation(req);
    if(errors.length){
        return res.render('edit-post', {errors});
    }
    const updatedStatement = db.prepare(`UPDATE posts SET title = ?, body = ? where id = ?`);
    updatedStatement.run(req.body.title, req.body.body, req.params.id);
    res.redirect(`/post/${req.params.id}`);

});


app.post("/create-post", mustBeLoggedIn, (req, res) => {
    const errors = sharedPostValidation(req);
    if(errors.length){
        res.render("create-post", {errors})
    }

    //save it into database
    const ourStatement = db.prepare(`INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)`);
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userId, new Date().toISOString());
    const getPostStatement = db.prepare(`SELECT * from posts where ROWID = ?`);
    const realPost = getPostStatement.get(result.lastInsertRowid);
    res.redirect(`/post/${realPost.id}`);
});

app.post('/delete-post/:id', mustBeLoggedIn, (req, res) => {
    const statement = db.prepare(`SELECT * from posts where id = ?`);
    const post = statement.get(req.params.id);

    //if post does not exits
    if(!post){
        return res.redirect('/no-post');
    }
    //if you are not the author re-direct to homepage
    if(post.authorid !== req.user.userId){
        return res.redirect('/');
    };

    const deleteStatement = db.prepare(`DELETE from posts where id = ?`);
    deleteStatement.run(req.params.id);
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