const express = require("express");
const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: false}));
app.use(express.static("public"));
app.use(function (req, res, next){
    res.locals.errors = [];
    next();
})

app.get('/', (req, res) => {
    res.render("homepage");
});

app.get('/login', (req, res) => {
    res.render("login");
})

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

    res.send("Thanks you for filling out the form");

    //Save the new user into a database
    //log the user in by giving them a cookie
})

app.listen(3000);