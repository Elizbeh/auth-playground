/*import express from "express"
import bcrypt from "bcrypt"
import cookieParser from "cookie-parser"

const PORT = 5000

const app = express()

app.use(express.json())

app.use(cookieParser())

const users = []
const sessions = {}

app.get("/", (req, res) => {
    res.status(200).json({message: "You are home"})
})

app.post("/register", async (req, res) => {
    const {email, password} = req.body

    const existingUser = users.find(u => u.email === email)
    if(existingUser) {
        res.status(401).json({error: "User already exist"})
        return
    }
    const hashed_pwd = await bcrypt.hash(password, 10)
    users.push({
        email,
        password: hashed_pwd
    })
    console.log(users)
    res.status(200).json({message: `User created`})
})

app.post("/login", async (req, res) => {
    const {email, password} = req.body

    const user = users.find(u => u.email === email)

    if(!user) {
        res.status(401).json({error: "User not found"})
        return
    }

    const isMatch =  await bcrypt.compare(password, user.password)
    if(!isMatch) {
        res.status(401).json({error: "Wrong credentials"})
        return
    }

    const sessionId = Math.random().toString(36).substring(2, 15)
    sessions[sessionId] = {
        email: user.email,
        createdAt: Date.now()
    }

    res.cookie("sessionId", sessionId, {httpOnly: true})
    res.status(200).json({message: "You are logged in", sessionId})
    
})

function requireLogin(req, res, next) {
    const sessionId = req.cookies.sessionId

    const session = sessions[sessionId]
    if(!session) {
        res.status(401).json({error: "Not logged in"})
        return
    }
    const now = Date.now()
    const maxAge = 15 * 60 * 1000
    if(now - session.createdAt > maxAge) {

        delete sessions[sessionId]

        res.clearCookie("sessionId")

        res.status(401).json({error: "Session expired, please log in again"})
        return
    }
    req.userEmail = session.email
    next()
}

app.get("/profile", requireLogin, (req, res) => {
    res.status(200).json({email: req.userEmail })
})

app.post("/logout", requireLogin, (req, res) => {
    const sessionId = req.cookies.sessionId

    delete sessions[sessionId]

    res.clearCookie("sessionId")
    res.status(200).json({message: "You have been logged out successfully"})
})

app.listen(PORT, () => {
    console.log(`Server running at port ${PORT}`)
})*/