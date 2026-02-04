import bcrypt from "bcrypt"
import { generateAccessToken, generateRefreshToken } from "../utils/tokenUtils.js"

// ========================
// In-memory stores (for learning only)
// ========================
const users = []          // Store registered users {email, hashed password}
let refreshTokens = []    // Store issued refresh tokens for revocation checks

// ========================
// Register a new user
// ========================
export const register = async (req, res) => {
    const { email, password } = req.body

    // Validate request body
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password required" })
    }

    // Check if user already exists
    if (users.find(u => u.email === email)) {
        return res.status(401).json({ error: "User already exist" })
    }

    // Hash the password securely
    const hashedPassword = await bcrypt.hash(password, 10)

    // Save user in memory
    users.push({ email, password: hashedPassword })

    // Send success response
    res.status(200).json({ message: "User created" })
}

// ========================
// Login user and issue tokens
// ========================
export const login = async (req, res) => {
    const { email, password } = req.body

    // Find user
    const user = users.find(u => u.email === email)
    if (!user) return res.status(401).json({ error: "User does not exist" })

    // Compare hashed passwords
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) return res.status(401).json({ error: "Wrong credentials" })
    
    // Generate access token (short-lived)
    const accessToken = generateAccessToken(user.email)

    // Generate refresh token (long-lived, for silent token renewal)
    const refreshToken = generateRefreshToken(user.email)

    // Store refresh token in memory for revocation support
    refreshTokens.push({ token: refreshToken, email: user.email, createdAt: Date.now() })

    // Send refresh token as httpOnly cookie (browser cannot access via JS)
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,       // Set to true in production (HTTPS)
        sameSite: "strict"   // Helps mitigate CSRF attacks
    })

    // Respond with access token for frontend to use in Authorization header
    res.status(200).json({ message: "You are logged in", accessToken })
}

// ========================
// Refresh access token
// ========================
export const refresh = (req, res) => {
    const token = req.cookies.refreshToken

    // Check if refresh token exists in server memory (not revoked)
    const storedToken = refreshTokens.find(rt => rt.token === token)
    if (!storedToken) return res.status(401).json({ error: "Refresh token revoked" })
    
    try {
        // Verify token validity
        const accessToken = generateAccessToken(storedToken.email)
        res.json({ accessToken })
    } catch {
        res.status(401).json({ error: "Invalid or expired token" })
    }
}

// ========================
// Logout user (revoke refresh token)
// ========================
export const logout = (req, res) => {
    const token = req.cookies.refreshToken

    // Remove refresh token from memory to prevent future use
    refreshTokens = refreshTokens.filter(rt => rt.token !== token)

    // Clear cookie from browser
    res.clearCookie("refreshToken")

    res.status(200).json({ message: "Logged out" })
}
