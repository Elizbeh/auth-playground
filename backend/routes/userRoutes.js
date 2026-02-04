import express from "express"
import { getProfile } from "../controllers/userController.js"
import requireAuth from "../middleware/requireAuth.js"

const userRouter = express.Router()

userRouter.get("/profile", requireAuth, getProfile)


export default userRouter