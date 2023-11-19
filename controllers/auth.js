const User = require('../models/User')
const {StatusCodes} = require('http-status-codes')
const {BadRequestError, UnauthenticatedError} = require('../errors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const register = async (req,res) => {

    /* const {name,email,password} = req.body

    if(!name || !email || !password)
    {
        throw new BadRequestError('Please provide name, email and password')
    } */

    //commented as now we will be passing hashed password 
    //const user = await User.create({...req.body})
    
    //password Hashing

    //commented as we are going to use the mongoose middleware
    /* const {name,email,password} = req.body

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password,salt)

    const tempUser = {
        name,email,password:hashedPassword
    } */

    const user = await User.create({...req.body})

    //move this token generation to the User Model (mongoose)
    /* const token = jwt.sign({ userId:user._id, name:user.name}, 'jwtsecret', {
        expiresIn:'30d'
    }) */

    const token = user.createJWT()

    //res.status(StatusCodes.CREATED).json({user})
    res.status(StatusCodes.CREATED).json({token, user:{name: user.name}})
}

const login = async (req,res) => {
    
    const {email,password} = req.body

    if(!email || !password)
    {
        throw new BadRequestError('Please provide name, email and password')
    } 

    const user = await User.findOne({email})

    if(!user)
    {
        throw new UnauthenticatedError('Invalid credentials')
    }

    //compare password

    const isPasswordCorrect = await user.comparePassword(password)

    if(!isPasswordCorrect)
    {
        throw new UnauthenticatedError('Invalid credentials')
    }

    const token = user.createJWT()
    res.status(StatusCodes.OK).json({token, user:{name: user.name}})
}

module.exports = {register, login}