const form = document.getElementById("checkForm");
const input = document.getElementById("url");
const result = document.getElementById("result");

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = input.value.trim();
  result.classList.remove("hidden");
  result.innerHTML = "<p>Checking URL...</p>";

  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    if (!response.ok) {
      result.innerHTML = `<p class="error">${escapeHtml(data.error || "Unable to check URL.")}</p>`;
      return;
    }

    const riskClass =
      data.risk === "LOW RISK" ? "risk-low" :
      data.risk === "SUSPICIOUS" ? "risk-suspicious" : "risk-high";

    const findings = data.findings.map(item => `
      <div class="finding ${item.level}">
        ${item.level === "good" ? "✓" : "⚠"} ${escapeHtml(item.text)}
      </div>
    `).join("");

    result.innerHTML = `
      <h2>Scan Result</h2>
      <div class="score ${riskClass}">${escapeHtml(data.risk)}</div>
      <p><strong>Risk Score:</strong> ${data.score}/100</p>
      <p><strong>Domain:</strong> ${escapeHtml(data.hostname)}</p>
      <p class="url">${escapeHtml(data.url)}</p>
      <h3>Findings</h3>
      ${findings}
      <p class="note">${escapeHtml(data.note)}</p>
    `;
  } catch (error) {
    result.innerHTML = `<p class="error">Could not connect to the server.</p>`;
  }
});

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}