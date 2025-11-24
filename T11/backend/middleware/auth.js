import { UserService } from "../services/user.js";

const authToken = (req, res, next) => {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(403).json({ message: "No token provided" });
    }

    const user = UserService.verify(token);
    if (!user) {
        return res.status(401).json({ message: "Invalid JWT Token" });
    }

    req.user = user;
    next();
};

export {
    authToken
};