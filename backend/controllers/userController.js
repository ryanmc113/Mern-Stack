const jwt = require('jsonwebtoken');
const bcyrpt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')
// @desc Register New User
// @route POST api/users
// @access Public
const registerUser = asyncHandler( async (req, res) =>{
    const { name, email, password } = req.body
    if(!name || !email || !password){
        res.status(400)
        throw new Error('Please ass all fields')
    }

    //Check if user exists
    const userExists = await User.findOne({email})

    if(userExists){
        res.status(400)
        throw new Error('User already exists')
    }

    // Hash password
    const salt = await bcyrpt.genSalt(10)
    const hashedPassword = await bcyrpt.hash(password, salt)
    const user = await User.create({
        name, 
        email,
        password: hashedPassword
    })
    if(user){
        res.status(201).json({
            _id: user.id,
            name: user.name,
            email: user.email,
            token: generateToken(user._id)
        })
    }else{
        res.status(400);
        throw new Error('Invalid user data')
    }
    //Create user
    
    
})

// @desc Authenticate a user
// @route POST api/login
// @access Public
const loginUser = asyncHandler( async (req, res) =>{
    const {email, password} = req.body

    //Check for user email
    const user = await User.findOne({email})

    if(user && (bcyrpt.compare(password, user.password))){
        res.json({
            _id: user.id,
            name: user.name,
            email: user.email,
            token: generateToken(user._id)
        })
    }else{
        res.status(400);
        throw new Error('Invalid credentials')
    }

})

// Generate JWT
const generateToken = (id) =>{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: '30d'
    })
}

// @desc Get user data
// @route GET api/users/me
// @access Private
const getMe = asyncHandler( async (req, res) =>{
    const {_id, name, email} = await User.findById(req.user.id);

    res.status(201).json({
        id: _id,
        name,
        email
    })
})


module.exports = {
    registerUser, loginUser, getMe
}