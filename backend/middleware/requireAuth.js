import jwt from "jsonwebtoken"

const JWT_SECRET = process.env.JWT_SECRET

// Middleware to protect routes using access token
const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization

    if (!authHeader) return res.status(401).json({ error: "No access token provided" })

    // Authorization: Bearer <token>
    const token = authHeader.split(" ")[1]

    try {
        const decoded = jwt.verify(token, JWT_SECRET)
        req.userEmail = decoded.email
        next()
    } catch {
        res.status(401).json({ error: "Invalid or expired access token" })
    }
}

export default requireAuth
