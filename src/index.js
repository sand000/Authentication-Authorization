const express = require("express")
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const {connection} = require("./config/db");
const {UserModel} = require("./Models/User.model");
require('dotenv').config();

const app = express();
app.use(express.json());


// home
app.get("/", async (req, res) => {
    res.send("Home");
});


// authentication middleware
const authentication = (req, res, next)=>{
  const token = req.headers?.authorization?.split(" ")[1];
  try{
    var decoded = jwt.verify(token, process.env.secret_key);
    req.body.email = decoded.email;
    next();
  }catch(e){
    res.send("Please login");
  }
}

// authorisation middleware
const authorisation = (permittedRole)=>{
    return async(req, res, next) => {
        const email = req.body.email;
        const user = await UserModel.findOne({email: email});
        const role = user.role;

        if(permittedRole.includes(role)){
            next();
        }else{
            res.send("Not authorised");
        }
  }
} 

// all users
app.get("/users", async(req, res)=>{
    const user = await UserModel.find();
    res.send(user);
});


// signup
app.post("/signup", async(req, res)=>{
    const {email, password} = req.body;
    bcrypt.hash(password, 8, async function(err,hash){
        if(err){
            res.send("something went wrong please signup later");
        }
        const new_user = new UserModel({
            email:email,
            password: hash
        })
        await new_user.save();
        res.send("signup successful");
    });
});


// login
app.post("/login", async (req, res) => {
    const {email, password} = req.body;
    const user = await UserModel.findOne({email});
    const hash_password = user.password;

    bcrypt.compare(password, hash_password, function(err,result){

        if(result){
            const token = jwt.sign({email: email}, process.env.secret_key)
            res.send({"msg":"login success", "token": token});
        }else{
            res.send("login failed");
        }
    })  
})


// dashboard
app.get("/dashboard", authentication, async(req, res) =>{
        res.send("dashboard data...");
});


// products no authentication | no authorization
app.get("/products", async(req, res) =>{
    res.send("here are the products in cart")
})


// cart authentication | no authorization
app.get("/products/cart", authentication, async(req, res) =>{
        res.send("here are the products in cart")
});


// create products authentication |  authorization
app.get("/products/createProduct", authentication, authorisation(["seller"]), async(req, res) =>{
            res.send("Product created")
})


//  authentication |  authorization
app.get("products/productFeedback", authentication, authorisation(["cutomer"]), async(req, res) =>{
    res.send("Product Feedback")
})

//  authentication |  authorization
app.get("/product/edit", authentication, authorisation(["ia", "instructor"]), async(req, res) =>{
    res.send("Product edit")
})

// listen
app.listen(8000, async()=>{
    try{
        await connection
        console.log("successfully connnected to db");
    }catch(e){
        console.log("error in connection");
    }
    console.log("listening on http://localhost:8000");
})