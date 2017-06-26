// Main starting point of the application
const express = require("express");
const http = require("http");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const mongoose = require("mongoose");

const router = require("./router");

// DB Setup
mongoose.connect("mongodb://localhost:auth/auth");

// App Setup
const app = express();
app.use(morgan("combined"));
app.use(bodyParser.json({ type: "*/*" }));
router(app);

// Server Setup
const PORT = process.env.PORT || 8080;
const server = http.createServer(app);
server.listen(PORT);
console.log(`Server listening on: ${PORT}`);
