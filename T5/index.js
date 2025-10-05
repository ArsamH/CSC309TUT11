#!/usr/bin/env node
"use strict";
const express = require("express");
const app = express();

app.use(express.json());
const data = [
  {
    title: "Buy groceries",
    description: "Milk, Bread, Eggs, Butter",
    completed: false,
  },
  {
    title: "Walk the dog",
    description: "Take Bella for a walk in the park",
    completed: true,
  },
  {
    title: "Read a book",
    description: "Finish reading 'The Great Gatsby'",
    completed: false,
  },
];

const port = (() => {
  const args = process.argv;

  if (args.length !== 3) {
    console.error("usage: node index.js port");
    process.exit(1);
  }

  const num = parseInt(args[2], 10);
  if (isNaN(num)) {
    console.error("error: argument must be an integer.");
    process.exit(1);
  }

  return num;
})();

app.get("/notes", (req, res) => {
  if (!req.query.done) {
    res.json(data);
  } else {
    if (done !== "true" && done !== "false") {
      return res.status(400).send("Bad request");
    }
    const completed = req.query.done === "true";
    const filtered = data.filter((value) => value.completed === completed);
    res.json(filtered);
  }
});

app.post("/notes", (req, res) => {
  console.log(req.body);

  const newVal = structuredClone(req.body);

  newVal.id = data.length;

  data.push(newVal);

  res.status(201).json(newVal);
});

app.get("/notes/:noteId", (req, res) => {
  const noteId = Number(req.params.noteId);
  if (isNaN(noteId)) {
    return res.status(400).send("Bad request");
  } else if (noteId < 0 || noteId >= data.length) {
    return res.status(404).send("Not found");
  } else {
    res.json(data[noteId]);
  }
});

app.patch("/notes/:noteId", (req, res) => {
  const noteId = Number(req.params.noteId);
  const done = req.query.done;
  if (done !== "true" && done !== "false") {
    res.status(400).send("Bad request");
  }

  if (noteId < 0 || noteId >= data.length) {
    res.status(404).send("Not found");
  }
  const completed = done === "true";
  data[noteId] = { ...data[noteId], completed: completed };
  res.status(200).json(data[noteId]);
});

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

server.on("error", (err) => {
  console.error(`cannot start server: ${err.message}`);
  process.exit(1);
});
