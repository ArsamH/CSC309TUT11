import dotenv from "dotenv";
dotenv.config();
import jwt from "jsonwebtoken";


const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key';

// In-memory database for User model
const users = [
    {
        id: 1,
        username: "johndoe",
        firstname: "John",
        lastname: "Doe",
        password: "123123",
        createdAt: new Date()
    }
];

class UserService {
    /**
     * Handles user login by verifying username and password.
     * @param {string} username - The username of the user.
     * @param {string} password - The password of the user.
     * @returns {string|null} - Returns a JWT token if login is successful, otherwise null.
     */
    static login(username, password) {
        const user = users.find((u) => u.username === username);
        
        if (!user || password !== user.password) {
            return null;
        }
    
        const token = jwt.sign(
            { id: user.id, username: user.username },
            SECRET_KEY,
            { expiresIn: "7d" }
        );

        return token;
    }

    /**
     * Verifies the JWT token and returns the user object (without password).
     * @param {string} token - The JWT token to verify.
     * @returns {Object|null} - Returns the user object without the password if verification is successful, otherwise null.
     */
    static verify(token) {
        try {
            const { id, username } = jwt.verify(token.split(" ")[1], SECRET_KEY);
            const user = users[id - 1];
    
            if (!user || username !== user.username) {
                return null;
            }
            
            const { password: _, ...user_no_passwd } = user;
            
            return user_no_passwd;
        }
        catch (error) {
            return null;
        }
    }

    /**
     * Creates a new user
     * @param {string} username - The username of the new user.
     * @param {string} firstname - The first name of the new user.
     * @param {string} lastname - The last name of the new user.
     * @param {string} password - The password of the new user.
     * @returns {boolean} - Returns true if user creation is successful, otherwise false.
     */
    static create(username, firstname, lastname, password) {
        if (users.some(u => u.username === username)) {
            return false;
        }
    
        users.push({
            id: users.length + 1, 
            username, firstname, lastname, password,
            createdAt: new Date()
        });

        console.log(users);

        return true;
    }
}

export { UserService };