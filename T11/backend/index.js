import express from "express";
import routes from "./routes.js";
// TODO: complete me (loading the necessary packages)

const app = express();

// TODO: complete me (CORS)
app.use(express.json());
app.use('', routes);

export default app;