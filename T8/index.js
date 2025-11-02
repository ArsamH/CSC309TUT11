#!/usr/bin/env node
'use strict';

require('dotenv').config();
const port = process.env.PORT || 3000;
const express = require("express");
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const app = express();

app.use(express.json());
app.set('view engine', 'ejs');
app.use('/static', express.static('./public'));

app.get('/', (_req, res) => {
    res.render('index');
});

const NUM_PARAGRAPHS_PER_REQUEST = 5;

app.get('/text', async (req, res) => {
    const start = parseInt(req.query.paragraph, 10) || 1;
    const end = start + NUM_PARAGRAPHS_PER_REQUEST;
    try {
        const [data, nextCount] = await prisma.$transaction([
            prisma.paragraph.findMany({
                where: {
                    id: {
                        gte: start,
                        lt: end,
                    },
                },
                orderBy: {
                    id: 'asc',
                },
            }),
            prisma.paragraph.count({
                where: { id: end },
            }),
        ]);
        const next = nextCount > 0;
        res.json({ data, next });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unknown database error"});
    }
});

app.post('/text/like', async (req, res) => {
    const paragraphId = parseInt(req.body.paragraph, 10);
    
    if (isNaN(paragraphId)) {
        return res.status(400).json({ message: "Invalid Paragraph ID"});
    }

    try {
        const para = await prisma.paragraph.update({
            where: { id: paragraphId },
            data: { likes: { increment: 1 } },
        });
        res.json({ data: { likes: para.likes } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unknown database error"});
    }
});

const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.on('error', (err) => {
    console.error(`cannot start server: ${err.message}`);
    process.exit(1);
});
