import express from "express";
import {loginController, profileController, registerController} from "./controllers/user.js";
import { authToken } from "./middleware/auth.js";

const router = express.Router();
router.post('/login', loginController);
router.get('/user/me', authToken, profileController);
router.post('/register', registerController);

export default router;