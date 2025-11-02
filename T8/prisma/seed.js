const { PrismaClient } = require('@prisma/client');
const fs = require('fs');
const path = require('path');
const prisma = new PrismaClient();

const chapterPath = path.join(__dirname, 'chapter1.txt');
const chapterText = fs.readFileSync(chapterPath, 'utf-8');
const paragraphs = chapterText
    .split(/\r?\n\s*\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);

function getRandomLikes(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function main() {
    for (const content of paragraphs) {
        const likes = getRandomLikes(0, 30);
        await prisma.paragraph.create({
            data: {
                content,
                likes,
            },
        });
    }
    console.log(`${paragraphs.length} paragraph objects created`);
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });