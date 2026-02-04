import express from "express"
import cookieParser from "cookie-parser"
import "dotenv/config"

// Import routers
import authRoutes from "./routes/authRoutes.js"
import userRoutes from "./routes/userRoutes.js"

const PORT = process.env.PORT || 5001

//MiddleWare
const app = express()
app.use(express.json())
app.use(cookieParser())

//Routes
app.use("/auth", authRoutes)
app.use("/user", userRoutes)

//Health Check
app.get("/", (req, res) => {
    res.status(200).json({message: "Welcome Home"})
})



//Start server

app.listen(PORT, () => console.log(`Server running at ${PORT}`))


