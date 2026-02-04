import jwt from "jsonwebtoken"

const JWT_SECRET = process.env.JWT_SECRET

export const generateAccessToken = (email) => {
    return jwt.sign({email}, JWT_SECRET, {expiresIn: "15m"})
}

export const generateRefreshToken = (email) => {
    return jwt.sign({email}, JWT_SECRET, {expiresIn: "7d"})
}