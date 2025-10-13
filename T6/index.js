#!/usr/bin/env node
"use strict";
const express = require("express");
const app = express();
const { PrismaClient } = require("@prisma/client");
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

const basicAuth = require("./middleware/basicAuth");
const prisma = new PrismaClient();

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

app.post("/users", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Invalid payload" });
  }
  try {
    const existingUser = await prisma.user.findUnique({
      where: { username },
    });
    if (existingUser) {
      return res
        .status(409)
        .json({ message: "A user with that username already exists" });
    }

    const newUser = await prisma.user.create({
      data: {
        username,
        password,
      },
    });
    return res.status(201).json(newUser);
  } catch {
    return res.status(500).json({ message: "error" });
  }
});

app.get("/notes", async (req, res) => {
  const done = req.query.done;
  if (done !== undefined) {
    if (done !== "true" && done !== "false") {
      return res.status(400).json({ message: "Invalid payload" });
    }
  }
  let notes;
  if (done === "true") {
    notes = await prisma.note.findMany({
      where: { completed: true, public: true },
    });
  } else if (done === "false") {
    notes = await prisma.note.findMany({
      where: { completed: false, public: true },
    });
  } else {
    notes = await prisma.note.findMany({
      where: { public: true },
    });
  }

  const response = notes.map((note) => ({
    id: note.id,
    title: note.title,
    description: note.description,
    completed: note.completed,
    public: note.public,
    userId: note.authorId,
  }));

  return res.status(200).json(response);
});

app.post("/notes", basicAuth, async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  const { title, description, completed, public: isPublic } = req.body;
  if (
    !title ||
    !description ||
    isPublic == undefined ||
    completed == undefined
  ) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  try {
    const newNote = await prisma.note.create({
      data: {
        title,
        description,
        completed,
        public: isPublic,
        authorId: req.user.id,
      },
    });

    const response = {
      id: newNote.id,
      title: newNote.title,
      description: newNote.description,
      completed: newNote.completed,
      public: newNote.public,
      userId: newNote.authorId,
    };

    return res.status(201).json(response);
  } catch {
    return res.status(500).json({ message: "error" });
  }
});

app.get("/hello", basicAuth, (req, res) => {
  if (req.user) {
    res.json(req.user);
  } else {
    res.status(401).json({ message: "Unauthorized" });
  }
});

app.get("/notes/:noteId", basicAuth, async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ message: "Not authenticated" });
  }
  const noteId = Number(req.params.noteId);
  if (isNaN(noteId)) {
    return res.status(404).json({ message: "Not found" });
  }
  try {
    const note = await prisma.note.findUnique({
      where: { id: noteId },
    });

    if (!note) {
      return res.status(404).json({ message: "Not found" });
    }

    if (note.authorId !== req.user.id) {
      return res.status(403).json({ message: "Not permitted" });
    }

    const response = {
      id: note.id,
      title: note.title,
      description: note.description,
      completed: note.completed,
      public: note.public,
      userId: note.authorId,
    };

    return res.status(200).json(response);
  } catch {
    return res.status(500).json({ message: "error" });
  }
});

app.patch("/notes/:noteId", basicAuth, async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ message: "Not authenticated" });
  }
  const noteId = Number(req.params.noteId);
  if (isNaN(noteId)) {
    return res.status(404).json({ message: "Not found" });
  }

  try {
    const note = await prisma.note.findUnique({
      where: { id: noteId },
    });

    if (!note) {
      return res.status(404).json({ message: "Not found" });
    }

    if (note.authorId !== req.user.id) {
      return res.status(403).json({ message: "Not permitted" });
    }

    const { title, description, completed, public: isPublic } = req.body;

    if (
      title === undefined &&
      description === undefined &&
      completed === undefined &&
      isPublic === undefined
    ) {
      return res.status(400).json({ message: "Invalid payload" });
    }

    const newNote = {};
    if (title !== undefined) {
      newNote.title = title;
    }
    if (description !== undefined) {
      newNote.description = description;
    }
    if (completed !== undefined) {
      newNote.completed = completed;
    }
    if (isPublic !== undefined) {
      newNote.public = isPublic;
    }

    const updated = await prisma.note.update({
      where: { id: noteId },
      data: newNote,
    });

    const response = {
      id: updated.id,
      title: updated.title,
      description: updated.description,
      completed: updated.completed,
      public: updated.public,
      userId: updated.authorId,
    };

    return res.status(200).json(response);
  } catch {
    return res.status(500).send({ message: "error" });
  }
});

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

server.on("error", (err) => {
  console.error(`cannot start server: ${err.message}`);
  process.exit(1);
});
