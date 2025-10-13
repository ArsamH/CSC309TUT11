const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

const basicAuth = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    req.user = null;
    return next();
  }

  // TODO:
  // 1. Parse authHeader to extract the username and password.
  const key = authHeader.split(" ")[1];
  const decoded = Buffer.from(key, "base64").toString("utf-8");
  const [username, password] = decoded.split(":");
  // 2. Check the database for the user with matching username and password.
  const user = await prisma.user.findFirst({
    where: { username, password },
  });
  // 3. If found, set req.user to it and allow the next middleware to run.
  // 4. If not, immediate respond with status code 401 and this JSON data: { message: "Invalid credentials" }

  if (!user) {
    return res.status(401).json({ message: "Invalid Credentials" });
  }
  req.user = user;
  next();
};

module.exports = basicAuth;
