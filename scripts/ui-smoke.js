const fs = require("node:fs/promises");
const path = require("node:path");
const { chromium } = require("playwright");

const baseUrl = process.env.AETHER_URL || "http://127.0.0.1:4173";
const viewports = [
  { name: "desktop", width: 1440, height: 1000 },
  { name: "mobile", width: 390, height: 844 },
];

async function main() {
  const artifactDirectory = path.join(__dirname, "..", "artifacts");
  await fs.mkdir(artifactDirectory, { recursive: true });
  const browser = await chromium.launch({ headless: true });

  try {
    for (const viewport of viewports) {
      const page = await browser.newPage({ viewport });
      const errors = [];
      page.on("console", (message) => {
        if (message.type() === "error") errors.push(message.text());
      });
      page.on("pageerror", (error) => errors.push(error.message));

      await page.goto(baseUrl, { waitUntil: "networkidle" });
      const result = {
        viewport: viewport.name,
        title: await page.title(),
        heading: await page.locator("h1").textContent(),
        errors,
      };
      await page.screenshot({ path: path.join(artifactDirectory, `${viewport.name}.png`), fullPage: true });
      console.log(JSON.stringify(result));
      if (errors.length) process.exitCode = 1;
      await page.close();
    }
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
