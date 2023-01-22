/* Imports */
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
// Config JSON response
app.use(express.json());

// Models
const User = require('./models/User');

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({message: 'Bem vindo a nossa Api'})
});

// Private Router
app.get("/user/:id", checkToken , async (req, res) => {
    const id= req.params.id;

    // Check if user exists
    const user = await User.findById({ _id: id}, '-password');

    if(!user) {
        return res.status(404).json({message: "Usuário não encontrado!"});
    }
    res.status(200).json(user);
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(!token) {
        return res.status(401).json({message: 'Acesso negado!'});
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next();
    } catch (error) {
        res.status(400).json({message: 'Token inválido!'});
    }
}

// Register User
app.post('/auth/register', async (req, res) => {
    const {name, email, password, confirmPassword} = await req.body;

    // Validations
    if(!name) {
        return res.status(422).json({message: 'O nome é obrigatório!'});
    }

    if(!email) {
        return res.status(422).json({message: 'O email é obrigatório!'});
    }

    if(!password) {
        return res.status(422).json({message: 'A senha é obrigatória!'});
    }

    if(!confirmPassword) {
        return res.status(422).json({message: 'A confirmação da senha é obrigatória!'});
    }

    if(password != confirmPassword) {
        return res.status(422).json({message: 'As senhas não são iguais!'});
    }

    // Check if user exists
    const userExists = await User.findOne({ email: email});

    if(userExists) {
        return res.status(422).json({message: "Email já cadastrado, por favor utilize outro email!"});
    }

    // Create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        user.save();
        res.status(201).json('Usuário criado com sucesso!');
    } catch (error) {
        console.log(error);
        res.status(500).json({message: 'Aconteceu um erro no servidor, tente novamente mais tarde!'});
    }
});

// Login User
app.post('/auth/login', async (req, res) => {
    const {email, password} = req.body;

    if(!email) {
        return res.status(422).json({message: 'O email é obrigatório!'});
    }

    if(!password) {
        return res.status(422).json({message: 'A senha é obrigatória!'});
    }

    // Check if user exists
    const user = await User.findOne({ email: email});

    if(!user) {
        return res.status(404).json({message: "Usuário não encontrado!"});
    }
    // Check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword) {
        return res.status(422).json({message: "Senha inválida!"});
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign({
            id: user._id
        }, secret);

        res.status(200).json({message: "Autenticação realizada com sucesso!", token});
    } catch (error) {
        console.log(error);
        res.status(500).json({message: 'Aconteceu um erro no servidor, tente novamente mais tarde!'}); 
    }

});


mongoose.connect(`mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@api-auth.hxujyd6.mongodb.net/?retryWrites=true&w=majority`).then( ()=> {
    console.log('Conexão com o banco realizada!');
    app.listen(3000);
}).catch( (err) => {
    console.log(err);
});
