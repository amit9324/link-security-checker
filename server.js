const express = require("express");
const path = require("path");
const { URL } = require("url");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const suspiciousKeywords = [
  "login", "verify", "verification", "password", "account",
  "secure", "update", "free", "bonus", "gift", "claim",
  "wallet", "payment", "signin"
];

function analyzeUrl(input) {
  let url;

  try {
    url = new URL(input);
  } catch {
    return { valid: false, error: "Invalid URL. Include http:// or https://." };
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    return { valid: false, error: "Only HTTP and HTTPS URLs are supported." };
  }

  const hostname = url.hostname.toLowerCase();
  const full = input.toLowerCase();
  const findings = [];
  let score = 0;

  if (url.protocol !== "https:") {
    score += 20;
    findings.push({ level: "warning", text: "The URL does not use HTTPS." });
  } else {
    findings.push({ level: "good", text: "HTTPS is enabled." });
  }

  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const ipv6 = hostname.includes(":");
  if (ipv4 || ipv6) {
    score += 20;
    findings.push({ level: "warning", text: "The URL uses an IP address instead of a normal domain." });
  }

  if (full.length > 150) {
    score += 10;
    findings.push({ level: "warning", text: "The URL is unusually long." });
  }

  if (url.username || url.password) {
    score += 20;
    findings.push({ level: "warning", text: "The URL contains user-information before the domain." });
  }

  if (hostname.includes("xn--")) {
    score += 15;
    findings.push({ level: "warning", text: "The domain contains Punycode (xn--). Verify the domain carefully." });
  }

  const atCount = (input.match(/@/g) || []).length;
  if (atCount > 0) {
    score += 15;
    findings.push({ level: "warning", text: "The URL contains an @ character." });
  }

  const keywordHits = suspiciousKeywords.filter(k => full.includes(k));
  if (keywordHits.length > 0) {
    score += Math.min(keywordHits.length * 5, 15);
    findings.push({
      level: "warning",
      text: `Suspicious-looking keyword(s): ${keywordHits.slice(0, 4).join(", ")}.`
    });
  }

  const subdomains = hostname.split(".").filter(Boolean);
  if (subdomains.length >= 5) {
    score += 10;
    findings.push({ level: "warning", text: "The domain has many subdomain levels." });
  }

  if (/[^\x00-\x7F]/.test(hostname)) {
    score += 10;
    findings.push({ level: "warning", text: "The domain contains non-ASCII characters." });
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    score += 5;
    findings.push({ level: "warning", text: `The URL uses a non-standard port (${url.port}).` });
  }

  if (findings.filter(f => f.level === "warning").length === 0) {
    findings.push({ level: "good", text: "No obvious suspicious URL patterns were detected." });
  }

  score = Math.min(score, 100);

  let risk;
  if (score <= 20) risk = "LOW RISK";
  else if (score <= 50) risk = "SUSPICIOUS";
  else risk = "HIGH RISK";

  return {
    valid: true,
    url: url.href,
    hostname,
    score,
    risk,
    findings,
    note: "This is a heuristic check. A low score does not guarantee that a website is safe."
  };
}

app.post("/api/check", (req, res) => {
  const input = typeof req.body.url === "string" ? req.body.url.trim() : "";
  if (!input) {
    return res.status(400).json({ error: "Please enter a URL." });
  }

  res.json(analyzeUrl(input));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Link Security Checker running on port ${PORT}`);
});