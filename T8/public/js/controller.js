/*
 * controller.js
 *
 * CSC309 Tutorial 8
 *
 * Complete me
 */

let currentParagraph = 1;
let moreData = true;
let isLoading = false;
let reachedEnd = false;
const dataContainer = document.getElementById("data");

async function fetchParagraphs(paragraphNumber) {
  try {
    const response = await fetch(`/text?paragraph=${paragraphNumber}`);
    return await response.json();
  } catch {
    return null;
  }
}

async function likeParagraph(paragraphId) {
  try {
    const response = await fetch("/text/like", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ paragraph: paragraphId }),
    });
    return await response.json();
  } catch {
    return null;
  }
}

function renderParagraphs(paragraphs) {
  paragraphs.forEach((paragraph) => {
    const paragraphDiv = document.createElement("div");
    paragraphDiv.id = `paragraph_${paragraph.id}`;
    const paragraphText = document.createElement("p");
    paragraphText.innerHTML = `${paragraph.content} <b>(Paragraph: ${paragraph.id})</b>`;

    const likeButton = document.createElement("button");
    likeButton.className = "btn like";
    likeButton.textContent = `Likes: ${paragraph.likes}`;
    likeButton.addEventListener("click", async () => {
      const result = await likeParagraph(paragraph.id);
      if (result && result.data) {
        likeButton.textContent = `Likes: ${result.data.likes}`;
      }
    });
    paragraphDiv.appendChild(paragraphText);
    paragraphDiv.appendChild(likeButton);
    dataContainer.appendChild(paragraphDiv);
  });
}

function showEndMessage() {
  if (!reachedEnd) {
    reachedEnd = true;
    const endMessage = document.createElement("p");
    endMessage.innerHTML = "<b>You have reached the end</b>";
    dataContainer.appendChild(endMessage);
  }
}

async function loadMoreParagraphs() {
  if (isLoading || reachedEnd || !moreData) {
    return;
  }

  isLoading = true;
  const result = await fetchParagraphs(currentParagraph);

  if (result && result.data) {
    renderParagraphs(result.data);
    currentParagraph += result.data.length;
    hasMoreData = result.next;

    if (!result.next) {
      showEndMessage();
    }
  }
  isLoading = false;
}

function handleScroll() {
  const scrollPosition = window.innerHeight + window.scrollY;
  const pageHeight = document.documentElement.scrollHeight;
  if (scrollPosition >= pageHeight - 100) {
    loadMoreParagraphs();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadMoreParagraphs();
});
window.addEventListener("scroll", handleScroll);
