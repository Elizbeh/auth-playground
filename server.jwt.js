import express from "express"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import cookieParser from "cookie-parser"
import "dotenv/config"

// ========================
// Config
// ========================

const JWT_SECRET = process.env.JWT_SECRET
const PORT = process.env.PORT || 5000

const app = express()

// ========================
// Middleware
// ========================

// Parse JSON request bodies
app.use(express.json())

// Parse cookies from incoming requests
app.use(cookieParser())

// ========================
// In-memory stores (for learning only)
// ========================

// Registered users (email + hashed password)
const users = []

// Stored refresh tokens for revocation control
let refreshTokens = []

// ========================
// Routes
// ========================

app.get("/", (req, res) => {
    res.status(200).json({ message: "You are home" })
})

/**
 * Register a new user
 */
app.post("/register", async (req, res) => {
    const { email, password } = req.body

    const existingUser = users.find(u => u.email === email)
    if (existingUser) {
        return res.status(401).json({ error: "User already exists" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    users.push({
        email,
        password: hashedPassword
    })

    res.status(200).json({ message: "User created" })
})

/**
 * Login user and issue tokens
 */
app.post("/login", async (req, res) => {
    const { email, password } = req.body

    const user = users.find(u => u.email === email)
    if (!user) {
        return res.status(401).json({ error: "User not found" })
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
        return res.status(401).json({ error: "Wrong credentials" })
    }

    // Short-lived access token (stateless)
    const accessToken = jwt.sign(
        { email: user.email },
        JWT_SECRET,
        { expiresIn: "15m" }
    )

    // Long-lived refresh token (server-controlled)
    const refreshToken = jwt.sign(
        { email: user.email },
        JWT_SECRET,
        { expiresIn: "7d" }
    )

    // Store refresh token for revocation support
    refreshTokens.push({
        token: refreshToken,
        email: user.email,
        createdAt: Date.now()
    })

    // Send refresh token as httpOnly cookie
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,      // true in production (HTTPS)
        sameSite: "strict"
    })

    res.status(200).json({
        message: "You are logged in",
        accessToken
    })
})

/**
 * Middleware to protect routes using access token
 */
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization

    if (!authHeader) {
        return res.status(401).json({ error: "No access token provided" })
    }

    const token = authHeader.split(" ")[1]

    try {
        const decoded = jwt.verify(token, JWT_SECRET)
        req.userEmail = decoded.email
        next()
    } catch {
        res.status(401).json({ error: "Invalid or expired access token" })
    }
}

/**
 * Protected route example
 */
app.get("/profile", requireAuth, (req, res) => {
    res.status(200).json({ email: req.userEmail })
})

/**
 * Refresh access token using refresh token
 */
app.post("/refresh", (req, res) => {
    const token = req.cookies.refreshToken

    if (!token) {
        return res.status(401).json({ error: "No refresh token" })
    }

    // Check if refresh token was revoked
    const storedToken = refreshTokens.find(rt => rt.token === token)
    if (!storedToken) {
        return res.status(401).json({ error: "Refresh token revoked" })
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET)

        const newAccessToken = jwt.sign(
            { email: decoded.email },
            JWT_SECRET,
            { expiresIn: "15m" }
        )

        res.json({ accessToken: newAccessToken })
    } catch {
        res.status(401).json({ error: "Invalid or expired refresh token" })
    }
})

/**
 * Logout user (revoke refresh token)
 */
app.post("/logout", (req, res) => {
    const token = req.cookies.refreshToken

    // Remove refresh token from server storage
    refreshTokens = refreshTokens.filter(rt => rt.token !== token)

    // Clear cookie from browser
    res.clearCookie("refreshToken")

    res.status(200).json({ message: "Logged out" })
})

// ========================
// Server
// ========================

app.listen(PORT, () => {
    console.log(`Server running at port ${PORT}`)
})
