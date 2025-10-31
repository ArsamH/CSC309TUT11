#!/usr/bin/env node
"use strict";

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

require("dotenv").config();
const express = require("express");
const { expressjwt: jwt } = require("express-jwt");
const jwtLib = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const { PrismaClient } = require("@prisma/client");
const multer = require("multer");

const prisma = new PrismaClient();
const app = express();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName);
  },
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only image files are allowed!"), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
});

app.use(express.json());
app.use("/uploads", express.static("uploads"));

const jwtMiddleware = jwt({
  secret: process.env.JWT_SECRET,
  algorithms: ["HS256"],
  credentialsRequired: false,
});

app.use(jwtMiddleware);

app.use((err, req, res, next) => {
  if (err.name === "UnauthorizedError") {
    req.auth = null;
    return next();
  }
  next();
});

const roleCheckMiddleware = (minimumRole) => {
  const roleLevels = { regular: 1, cashier: 2, manager: 3, superuser: 4 };

  return async (req, res, next) => {
    if (!req.auth || !req.auth.userId) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: { role: true },
      });

      if (!user) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const userLevel = roleLevels[user.role] || 0;
      const requiredLevel = roleLevels[minimumRole] || 0;

      if (userLevel < requiredLevel) {
        return res.status(403).json({ error: "Forbidden" });
      }

      req.user = user;
      next();
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  };
};

const validateUtorid = (utorid) => {
  return typeof utorid === "string" && /^[a-zA-Z0-9]{7,8}$/.test(utorid);
};

const validateName = (name) => {
  return typeof name === "string" && name.length >= 1 && name.length <= 50;
};

const validateEmail = (email) => {
  return (
    typeof email === "string" && /^[^\s@]+@(mail\.)?utoronto\.ca$/.test(email)
  );
};

const validatePassword = (password) => {
  if (
    typeof password !== "string" ||
    password.length < 8 ||
    password.length > 20
  ) {
    return false;
  }
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  return hasUppercase && hasLowercase && hasNumber && hasSpecial;
};

const validateBirthday = (birthday) => {
  if (typeof birthday !== "string") {
    return false;
  }
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(birthday)) {
    return false;
  }
  const date = new Date(birthday);
  return date instanceof Date && !isNaN(date);
};

const resetRateLimiter = new Map();

app.post("/auth/tokens", async (req, res) => {
  try {
    const { utorid, password, ...extraFields } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid || !password) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const user = await prisma.user.findUnique({
      where: { utorid },
    });

    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const token = jwtLib.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      expiresAt: expiresAt.toISOString(),
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/auth/resets", async (req, res) => {
  try {
    const { utorid, ...extraFields } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const user = await prisma.user.findUnique({
      where: { utorid },
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found" });
    }

    const lastRequest = resetRateLimiter.get(utorid);
    const now = Date.now();

    if (lastRequest && now - lastRequest < 60000) {
      return res.status(429).json({ error: "Too Many Requests" });
    }

    resetRateLimiter.set(utorid, now);
    for (const [id, timestamp] of resetRateLimiter.entries()) {
      if (now - timestamp > 60000) {
        resetRateLimiter.delete(id);
      }
    }

    const resetToken = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);

    if (user) {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetToken,
          expiresAt,
        },
      });
    }

    res.status(202).json({
      expiresAt: expiresAt.toISOString(),
      resetToken,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/auth/resets/:resetToken", async (req, res) => {
  try {
    const { resetToken } = req.params;
    const { utorid, password, ...extraFields } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid || !password) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const user = await prisma.user.findUnique({
      where: { resetToken },
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found" });
    }

    if (user.utorid !== utorid) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!user.expiresAt || new Date() > user.expiresAt) {
      return res.status(410).json({ error: "Gone" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        resetToken: null,
        expiresAt: null,
        lastLogin: new Date(),
      },
    });

    res.status(200).json({ message: "OK" });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/users", roleCheckMiddleware("cashier"), async (req, res) => {
  try {
    const { utorid, name, email, ...extraFields } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid || !name || !email) {
      return res.status(400).json({ error: "Bad Request" });
    }
    if (
      !validateUtorid(utorid) ||
      !validateName(name) ||
      !validateEmail(email)
    ) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const existingUser = await prisma.user.findUnique({
      where: { utorid },
    });

    if (existingUser) {
      return res.status(409).json({ error: "Conflict" });
    }
    const existingEmail = await prisma.user.findUnique({
      where: { email },
    });

    if (existingEmail) {
      return res.status(409).json({ error: "Conflict" });
    }

    const resetToken = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const user = await prisma.user.create({
      data: {
        utorid,
        name,
        email,
        resetToken,
        expiresAt,
        verified: false,
      },
    });

    res.status(201).json({
      id: user.id,
      utorid: user.utorid,
      name: user.name,
      email: user.email,
      verified: user.verified,
      expiresAt: user.expiresAt.toISOString(),
      resetToken: user.resetToken,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/users", roleCheckMiddleware("manager"), async (req, res) => {
  try {
    const {
      name,
      role,
      verified,
      activated,
      page = "1",
      limit = "10",
    } = req.query;

    const pageNumber = parseInt(page, 10);
    const limitNumber = parseInt(limit, 10);

    if (
      isNaN(pageNumber) ||
      pageNumber < 1 ||
      isNaN(limitNumber) ||
      limitNumber < 1
    ) {
      return res.status(400).json({ error: "Bad Request" });
    }
    const filters = {};

    if (name) {
      filters.OR = [
        { utorid: { contains: name } },
        { name: { contains: name } },
      ];
    }

    if (role) {
      filters.role = role;
    }

    if (verified !== undefined) {
      filters.verified = verified === "true";
    }

    if (activated === "true") {
      filters.lastLogin = { not: null };
    } else if (activated === "false") {
      filters.lastLogin = null;
    }

    const count = await prisma.user.count({ where: filters });

    const skip = (pageNumber - 1) * limitNumber;
    const results = await prisma.user.findMany({
      where: filters,
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        birthday: true,
        role: true,
        points: true,
        createdAt: true,
        lastLogin: true,
        verified: true,
        avatarUrl: true,
      },
      skip,
      take: limitNumber,
    });

    res.status(200).json({
      count,
      results,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/users/me", roleCheckMiddleware("regular"), async (req, res) => {
  try {
    const userId = req.auth.userId;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        birthday: true,
        role: true,
        points: true,
        createdAt: true,
        lastLogin: true,
        verified: true,
        avatarUrl: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found" });
    }

    const now = new Date();
    const usedPromotions = await prisma.userPromotion.findMany({
      where: { userId },
      select: { promotionId: true },
    });

    const usedPromotionIds = usedPromotions.map(
      (usedPromotion) => usedPromotion.promotionId
    );

    const promotions = await prisma.promotion.findMany({
      where: {
        type: "onetime",
        startTime: { lte: now },
        endTime: { gte: now },
        id: { notIn: usedPromotionIds },
      },
      select: {
        id: true,
        name: true,
        minSpending: true,
        rate: true,
        points: true,
      },
    });

    res.status(200).json({
      ...user,
      birthday: user.birthday
        ? user.birthday.toISOString().split("T")[0]
        : null,
      promotions,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.patch(
  "/users/me",
  roleCheckMiddleware("regular"),
  upload.single("avatar"),
  async (req, res) => {
    try {
      const userId = req.auth.userId;
      const { name, email, birthday, avatar, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        name === undefined &&
        email === undefined &&
        birthday === undefined &&
        !req.file
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (name !== undefined && !validateName(name)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (email !== undefined && !validateEmail(email)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (birthday !== undefined && !validateBirthday(birthday)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const updateData = {};
      if (name !== undefined) {
        updateData.name = name;
      }
      if (email !== undefined) {
        updateData.email = email;
      }
      if (birthday !== undefined) {
        updateData.birthday = new Date(birthday);
      }
      if (req.file) {
        updateData.avatarUrl = `/uploads/${req.file.filename}`;
      }

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: updateData,
        select: {
          id: true,
          utorid: true,
          name: true,
          email: true,
          birthday: true,
          role: true,
          points: true,
          createdAt: true,
          lastLogin: true,
          verified: true,
          avatarUrl: true,
        },
      });

      res.status(200).json({
        ...updatedUser,
        birthday: updatedUser.birthday
          ? updatedUser.birthday.toISOString().split("T")[0]
          : null,
      });
    } catch (error) {
      if (error instanceof multer.MulterError) {
        return res.status(400).json({ error: "Bad Request" });
      }

      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.patch(
  "/users/me/password",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const userId = req.auth.userId;
      const { old, new: newPassword, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (!old || !newPassword) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (!validatePassword(newPassword)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { passwordHash: true },
      });
      if (!user || !user.passwordHash) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const passwordMatch = await bcrypt.compare(old, user.passwordHash);
      if (!passwordMatch) {
        return res.status(403).json({ error: "Forbidden" });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash: newPasswordHash },
      });

      res.status(200).json({ message: "OK" });
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get("/users/:userId", roleCheckMiddleware("cashier"), async (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);

    if (isNaN(userId)) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const userSelect = {
      id: true,
      utorid: true,
      name: true,
      points: true,
      verified: true,
    };

    if (req.user.role === "manager" || req.user.role === "superuser") {
      userSelect.email = true;
      userSelect.birthday = true;
      userSelect.role = true;
      userSelect.createdAt = true;
      userSelect.lastLogin = true;
      userSelect.avatarUrl = true;
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: userSelect,
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found" });
    }

    const now = new Date();

    const usedPromotions = await prisma.userPromotion.findMany({
      where: { userId },
      select: { promotionId: true },
    });

    const usedPromotionIds = usedPromotions.map(
      (usedPromotion) => usedPromotion.promotionId
    );

    const promotions = await prisma.promotion.findMany({
      where: {
        type: "onetime",
        startTime: { lte: now },
        endTime: { gte: now },
        id: { notIn: usedPromotionIds },
      },
      select: {
        id: true,
        name: true,
        minSpending: true,
        rate: true,
        points: true,
      },
    });

    res.status(200).json({
      ...user,
      promotions,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.patch(
  "/users/:userId",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const userId = parseInt(req.params.userId, 10);

      if (isNaN(userId)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const { email, verified, suspicious, role, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        email === undefined &&
        verified === undefined &&
        suspicious === undefined &&
        role === undefined
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (email !== undefined && email !== null && !validateEmail(email)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        verified !== undefined &&
        verified !== null &&
        (typeof verified !== "boolean" || verified !== true)
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        suspicious !== undefined &&
        suspicious !== null &&
        typeof suspicious !== "boolean"
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        role !== undefined &&
        role !== null &&
        role !== "regular" &&
        role !== "cashier" &&
        role !== "manager" &&
        role !== "superuser"
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (req.user.role === "manager" && role !== undefined && role !== null) {
        if (role !== "regular" && role !== "cashier") {
          return res.status(403).json({ error: "Forbidden" });
        }
      }

      const existingUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, utorid: true, name: true, suspicious: true },
      });

      if (!existingUser) {
        return res.status(404).json({ error: "Not Found" });
      }
      if (role === "cashier") {
        const isSus =
          suspicious !== undefined && suspicious !== null
            ? suspicious
            : existingUser.suspicious;
        if (isSus) {
          return res.status(400).json({ error: "Bad Request" });
        }
      }

      const response = {
        id: existingUser.id,
        utorid: existingUser.utorid,
        name: existingUser.name,
      };

      const updateData = {};
      if (email !== undefined && email !== null) {
        updateData.email = email;
        response.email = email;
      }
      if (verified !== undefined && verified !== null) {
        updateData.verified = verified;
        response.verified = verified;
      }
      if (suspicious !== undefined && suspicious !== null) {
        updateData.suspicious = suspicious;
        response.suspicious = suspicious;
      }
      if (role !== undefined && role !== null) {
        updateData.role = role;
        response.role = role;
      }

      await prisma.user.update({
        where: { id: userId },
        data: updateData,
      });
      res.status(200).json(response);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post("/transactions", roleCheckMiddleware("cashier"), async (req, res) => {
  try {
    const {
      utorid,
      type,
      spent,
      amount,
      relatedId,
      promotionIds,
      remark,
      ...extraFields
    } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid || !type) {
      return res.status(400).json({ error: "Bad Request" });
    }
    const customer = await prisma.user.findUnique({
      where: { utorid },
    });

    if (!customer) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const currentUser = await prisma.user.findUnique({
      where: { id: req.auth.userId },
      select: { utorid: true, role: true, suspicious: true },
    });

    if (!currentUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    if (type === "purchase") {
      if (
        currentUser.role !== "cashier" &&
        currentUser.role !== "manager" &&
        currentUser.role !== "superuser"
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }

      if (
        spent === undefined ||
        spent === null ||
        typeof spent !== "number" ||
        spent <= 0
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      let promotions = [];
      if (promotionIds) {
        const now = new Date();
        promotions = await prisma.promotion.findMany({
          where: {
            id: { in: promotionIds },
            startTime: { lte: now },
            endTime: { gte: now },
          },
        });

        if (promotions.length !== promotionIds.length) {
          return res.status(400).json({ error: "Bad Request" });
        }

        for (const promotion of promotions) {
          if (promotion.minSpending && spent < promotion.minSpending) {
            return res.status(400).json({ error: "Bad Request" });
          }
          if (promotion.type === "onetime") {
            const alreadyUsed = await prisma.userPromotion.findUnique({
              where: {
                userId_promotionId: {
                  userId: customer.id,
                  promotionId: promotion.id,
                },
              },
            });

            if (alreadyUsed) {
              return res.status(400).json({ error: "Bad Request" });
            }
          }
        }
      }
      let earned = Math.round(spent / 0.25);
      for (const promotion of promotions) {
        if (promotion.rate) {
          earned += Math.round((spent / 0.25) * promotion.rate);
        }
        if (promotion.points) {
          earned += promotion.points;
        }
      }
      const transaction = await prisma.transaction.create({
        data: {
          type: "purchase",
          amount: earned,
          spent: spent,
          remark: remark || "",
          suspicious: currentUser.suspicious,
          userId: customer.id,
          createdById: req.auth.userId,
        },
      });
      if (promotionIds && promotionIds.length > 0) {
        for (const promotionId of promotionIds) {
          await prisma.transactionPromotion.create({
            data: {
              transactionId: transaction.id,
              promotionId: promotionId,
            },
          });
          const promo = promotions.find((promo) => promo.id === promoId);
          if (promo && promo.type === "onetime") {
            await prisma.userPromotion.create({
              data: {
                userId: customer.id,
                promotionId: promoId,
              },
            });
          }
        }
      }
      if (!currentUser.suspicious) {
        await prisma.user.update({
          where: { id: customer.id },
          data: { points: customer.points + earned },
        });
      }

      return res.status(201).json({
        id: transaction.id,
        utorid: utorid,
        type: "purchase",
        spent: spent,
        earned: earned,
        remark: transaction.remark,
        promotionIds: promotionIds || [],
        createdBy: currentUser.utorid,
      });
    }

    if (type === "adjustment") {
      if (currentUser.role !== "manager" && currentUser.role !== "superuser") {
        return res.status(403).json({ error: "Forbidden" });
      }
      if (amount === undefined || amount === null) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (typeof amount !== "number") {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (relatedId === undefined || relatedId === null) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (typeof relatedId !== "number") {
        return res.status(400).json({ error: "Bad Request" });
      }
      const relatedTransaction = await prisma.transaction.findUnique({
        where: { id: relatedId },
      });

      if (!relatedTransaction) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const transaction = await prisma.transaction.create({
        data: {
          type: "adjustment",
          amount: amount,
          relatedId: relatedId,
          remark: remark || "",
          suspicious: false,
          userId: customer.id,
          createdById: req.auth.userId,
        },
      });
      await prisma.user.update({
        where: { id: customer.id },
        data: { points: customer.points + amount },
      });

      return res.status(201).json({
        id: transaction.id,
        utorid: utorid,
        amount: amount,
        type: "adjustment",
        relatedId: relatedId,
        remark: transaction.remark,
        promotionIds: promotionIds || [],
        createdBy: currentUser.utorid,
      });
    }
    return res.status(400).json({ error: "Bad Request" });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/transactions", roleCheckMiddleware("manager"), async (req, res) => {
  try {
    const {
      name,
      createdBy,
      suspicious,
      promotionId,
      type,
      relatedId,
      amount,
      operator,
      page = "1",
      limit = "10",
    } = req.query;

    const pageNumber = parseInt(page, 10);
    const limitNumber = parseInt(limit, 10);

    if (
      isNaN(pageNumber) ||
      pageNumber < 1 ||
      isNaN(limitNumber) ||
      limitNumber < 1
    ) {
      return res.status(400).json({ error: "Bad Request" });
    }
    if (relatedId !== undefined && type === undefined) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (
      (amount !== undefined && operator === undefined) ||
      (amount === undefined && operator !== undefined)
    ) {
      return res.status(400).json({ error: "Bad Request" });
    }
    if (operator !== undefined && operator !== "gte" && operator !== "lte") {
      return res.status(400).json({ error: "Bad Request" });
    }

    const filters = {};

    if (name) {
      filters.user = {
        OR: [{ utorid: name }, { name: name }],
      };
    }

    if (createdBy) {
      filters.createdBy = {
        utorid: createdBy,
      };
    }

    if (suspicious !== undefined) {
      filters.suspicious = suspicious === "true";
    }
    if (type) {
      filters.type = type;
    }

    if (relatedId !== undefined) {
      const relatedIdNum = parseInt(relatedId, 10);
      if (isNaN(relatedIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      filters.relatedId = relatedIdNum;
    }
    if (amount !== undefined) {
      const amountNum = parseInt(amount, 10);
      if (isNaN(amountNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (operator === "gte") {
        filters.amount = { gte: amountNum };
      } else if (operator === "lte") {
        filters.amount = { lte: amountNum };
      }
    }

    let possibleTransactionIds = null;
    if (promotionId !== undefined) {
      const promotionIdNum = parseInt(promotionId, 10);
      if (isNaN(promotionIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const transactionPromotions = await prisma.transactionPromotion.findMany({
        where: { promotionId: promotionIdNum },
        select: { transactionId: true },
      });

      possibleTransactionIds = transactionPromotions.map(
        (tp) => tp.transactionId
      );

      if (possibleTransactionIds.length === 0) {
        return res.status(200).json({ count: 0, results: [] });
      }

      filters.id = { in: possibleTransactionIds };
    }

    const count = await prisma.transaction.count({ where: filters });

    const skip = (pageNumber - 1) * limitNumber;
    const transactions = await prisma.transaction.findMany({
      where: filters,
      include: {
        user: {
          select: { utorid: true },
        },
        createdBy: {
          select: { utorid: true },
        },
        promotions: {
          select: { promotionId: true },
        },
      },
      skip,
      take: limitNumber,
    });
    const results = transactions.map((t) => {
      const result = {
        id: t.id,
        utorid: t.user.utorid,
        amount: t.amount,
        type: t.type,
        promotionIds: t.promotions.map((p) => p.promotionId),
        suspicious: t.suspicious,
        remark: t.remark || "",
        createdBy: t.createdBy.utorid,
      };

      if (t.spent !== null) {
        result.spent = t.spent;
      }
      if (t.relatedId !== null) {
        result.relatedId = t.relatedId;
      }
      if (t.redeemed !== null) {
        result.redeemed = t.redeemed;
      }

      return result;
    });

    res.status(200).json({
      count,
      results,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

server.on("error", (err) => {
  console.error(`cannot start server: ${err.message}`);
  process.exit(1);
});
