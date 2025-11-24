import { UserService } from "../services/user.js";

function loginController(req, res) {
    const { username, password } = req.body;
    const data = UserService.login(username, password);

    if (!data) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    res.json({ token: data });
}

function profileController(req, res) {
    res.json({ user: req.user });
}

function registerController(req, res) {
    const { username, firstname, lastname, password } = req.body;

    if (!username || !password || !firstname || !lastname) {
        return res.status(400).json({ message: "All fields are required" });
    }

    const result = UserService.create(username, firstname, lastname, password);

    if (!result) {
        return res.status(409).json({ message: "User Name already exists" });
    }

    res.status(201).json({ message: "User registered successfully" });
}

export {
    loginController,
    profileController,
    registerController
};