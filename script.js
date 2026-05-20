document.getElementById("year").textContent = new Date().getFullYear();

const cursor    = document.getElementById("cursor");
const cursorDot = document.getElementById("cursorDot");
let mouseX = 0, mouseY = 0, cursorX = 0, cursorY = 0;

document.addEventListener("mousemove", e => {
  mouseX = e.clientX; mouseY = e.clientY;
  cursorDot.style.left = mouseX + "px";
  cursorDot.style.top  = mouseY + "px";
});

(function animateCursor() {
  cursorX += (mouseX - cursorX) * 0.12;
  cursorY += (mouseY - cursorY) * 0.12;
  cursor.style.left = cursorX + "px";
  cursor.style.top  = cursorY + "px";
  requestAnimationFrame(animateCursor);
})();

document.querySelectorAll("a, button, .stack-card, input").forEach(el => {
  el.addEventListener("mouseenter", () => cursor.classList.add("hover"));
  el.addEventListener("mouseleave", () => cursor.classList.remove("hover"));
});

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const delay = parseInt(entry.target.dataset.delay || 0);
      setTimeout(() => entry.target.classList.add("revealed"), delay);
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.1, rootMargin: "0px 0px -40px 0px" });

document.querySelectorAll(".reveal-block").forEach(el => observer.observe(el));

document.getElementById("targetUrl").addEventListener("keydown", e => {
  if (e.key === "Enter") startScan();
});

let currentData = null;

async function startScan() {
  const btn        = document.getElementById("btnScan");
  const btnText    = document.getElementById("btnText");
  const btnIcon    = document.getElementById("btnIcon");
  const urlInput   = document.getElementById("targetUrl");
  const resultsDiv = document.getElementById("results");

  const existingErr = document.getElementById("scan-error");
  if (existingErr) existingErr.remove();

  if (!urlInput.value.trim()) {
    urlInput.focus();
    return;
  }

  btn.disabled = true;
  btnText.textContent = "Analyzing";
  btnIcon.className = "fa-solid fa-circle-notch spinning";

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlInput.value.trim() })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.details || data.error || "Technical failure");

    currentData = data;

    resultsDiv.classList.remove("hidden");
    resultsDiv.classList.remove("revealed");
    void resultsDiv.offsetWidth;
    observer.observe(resultsDiv);

    const gradeEl = document.getElementById("res-grade");
    gradeEl.textContent = data.grade;
    gradeEl.className = "grade-value " +
      (data.score >= 80 ? "good" : data.score >= 50 ? "medium" : "bad");
    document.getElementById("res-score").textContent = data.score;

    document.getElementById("res-ssl-v").textContent      = data.ssl.protocol || "TLS";
    document.getElementById("res-ssl-grade").textContent  = data.ssl.grade    || "—";
    document.getElementById("res-ssl-expiry").textContent = data.ssl.expiry   || "—";

    const sslGrade = (data.ssl.grade || "").toUpperCase();
    let sslDesc = "Certificate verified successfully.";
    if      (sslGrade === "A+" || sslGrade === "A") sslDesc = "Excellent SSL/TLS configuration.";
    else if (sslGrade === "B")                      sslDesc = "Acceptable configuration, room for improvement.";
    else if (sslGrade === "C" || sslGrade === "D")  sslDesc = "Weak deployment, review recommended.";
    else if (sslGrade === "F")                      sslDesc = "⚠️ Critical security flaws detected in TLS handshake.";
    else if (!data.ssl.grade)                       sslDesc = "SSL Labs cache pending. Please retry in a few moments.";
    document.getElementById("res-ssl-desc").textContent = sslDesc;

    document.getElementById("list-http").innerHTML =
      row("HSTS",              data.headers.hsts)        +
      row("CSP",               data.headers.csp)         +
      row("X-Frame-Options",   data.headers.xframe)      +
      row("X-Content-Type",    data.headers.xcontent)    +
      row("Referrer-Policy",   data.headers.referrer)    +
      row("Permissions-Policy",data.headers.permissions) +
      rowPlain("Server Info",  data.headers.server)      +
      rowPlain("Powered By",   data.headers.poweredBy);

    document.getElementById("list-dns").innerHTML =
      row("SPF record",   data.dns.spf)   +
      row("DMARC record", data.dns.dmarc) +
      row("MX (email)",   data.dns.mx)  +
      rowPlain("NS Nodes",data.dns.ns)    +
      rowPlain("IP Address", data.dns.ip);

    const cardIp = document.getElementById("card-ip");
    if (data.ip) {
      document.getElementById("list-ip").innerHTML =
        rowPlain("City",    data.ip.city    || "—") +
        rowPlain("Country", data.ip.country || "—") +
        rowPlain("Region",  data.ip.region  || "—") +
        rowPlain("ASN/Org", data.ip.org     || "—");
      cardIp.style.display = "";
    } else {
      document.getElementById("list-ip").innerHTML =
        `<div class="detail-row"><span class="label" style="color:var(--muted)">Unresolved IP or geolocation data unavailable</span></div>`;
    }

    const httpStatus = data.httpStatus;
    document.getElementById("list-extras").innerHTML =
      row("robots.txt",     data.extras.robots      ? "✅ PRESENT"      : "⚠️ NOT FOUND") +
      row("security.txt",   data.extras.securityTxt ? "✅ PRESENT"      : "⚠️ NOT FOUND") +
      rowPlain("HTTP Status", httpStatus ? String(httpStatus) : "No response");

    setTimeout(() => {
      resultsDiv.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 200);

  } catch (err) {
    showError(err.message);
    resultsDiv.classList.add("hidden");
  } finally {
    btn.disabled = false;
    btnText.textContent = "Audit Target";
    btnIcon.className = "fa-solid fa-arrow-right";
    btnIcon.id = "btnIcon";
  }
}

function row(label, value) {
  if (!value) return "";
  const isOk   = value.includes("✅");
  const isWarn = value.includes("⚠️") || value.toUpperCase().includes("MISSING") || value.toUpperCase().includes("NOT ") || value.toUpperCase().includes("VULNERABLE");
  const isBad  = value.includes("❌");
  const cls = isBad ? "bad" : isOk ? "ok" : isWarn ? "warn" : "";
  const display = value.length > 55 ? value.substring(0, 52) + "…" : value;
  return `<div class="detail-row">
    <span class="label">${label}</span>
    <span class="value ${cls}" title="${value}">${display}</span>
  </div>`;
}

function rowPlain(label, value) {
  if (!value) return "";
  const display = value.length > 55 ? value.substring(0, 52) + "…" : value;
  return `<div class="detail-row">
    <span class="label">${label}</span>
    <span class="value" style="color:var(--muted)" title="${value}">${display}</span>
  </div>`;
}

function showError(msg) {
  const existing = document.getElementById("scan-error");
  if (existing) existing.remove();
  const el = document.createElement("p");
  el.id = "scan-error";
  el.style.cssText = "font-family:var(--font-mono);font-size:13px;color:#f87171;margin-top:12px;";
  el.textContent = "⚠️ " + msg;
  document.querySelector(".scanner-card").appendChild(el);
  setTimeout(() => el.remove(), 6000);
}

function pdfClean(str) {
  if (!str) return "-";
  return str
    .replace(/✅\s*/g, "[OK] ")
    .replace(/⚠️\s*/g, "[!] ")
    .replace(/❌\s*/g, "[X] ")
    .replace(/[^\x00-\x7E]/g, "")
    .replace(/\s+/g, " ")
    .trim() || "-";
}

// Actualizado para usar las palabras clave en inglés
function pdfColor(cleanVal, accent, warn, bad, neutral) {
  if (cleanVal.includes("[OK]"))  return accent;
  if (cleanVal.includes("[X]") || cleanVal.toUpperCase().includes("VULNERABLE"))   return bad;
  if (cleanVal.includes("[!]") || cleanVal.toUpperCase().includes("MISSING") || cleanVal.toUpperCase().includes("NOT FOUND"))   return warn;
  return neutral;
}

function downloadPDF() {
  if (!currentData) return;
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  const accent  = [94, 234, 212];
  const dark    = [8, 12, 20];
  const panel   = [17, 24, 39];
  const muted   = [100, 120, 140];
  const textCol = [220, 230, 240];
  const warn    = [250, 204, 21];
  const bad     = [248, 113, 113];

  doc.setFillColor(...dark);
  doc.rect(0, 0, 210, 297, "F");

  doc.setFillColor(...panel);
  doc.rect(0, 0, 210, 38, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(17);
  doc.setTextColor(...accent);
  doc.text("ASIR Security Auditor", 20, 15);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(...muted);
  doc.text("Technical Infrastructure Report  |  samuelcedillasanchez.com", 20, 23);
  doc.text("Generated: " + new Date().toLocaleString("en-US"), 20, 30);

  doc.setFontSize(10.5);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(...muted);
  doc.text("Target Domain:", 20, 46);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(...accent);
  doc.text(currentData.domain, 52, 46);

  doc.setFont("helvetica", "bold");
  doc.setTextColor(...muted);
  doc.text("Security Grade:", 20, 54);
  doc.setFont("helvetica", "normal");
  const gradeColor = currentData.score >= 80 ? accent : currentData.score >= 50 ? warn : bad;
  doc.setTextColor(...gradeColor);
  doc.text(currentData.grade + "  (Score: " + currentData.score + "/100)", 55, 54);

  doc.setDrawColor(...accent);
  doc.setLineWidth(0.4);
  doc.line(20, 60, 190, 60);

  let y = 69;

  function pdfSection(title) {
    doc.setFontSize(10);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(...accent);
    doc.text(title, 20, y);
    y += 7;
  }

  // Corregido el buscador de color para dar soporte al formateo dinámico en inglés
  function pdfRow(label, rawVal, colorize) {
    if (colorize === undefined) colorize = true;
    const clean = pdfClean(rawVal);
    const col   = colorize ? pdfColor(clean, accent, warn, bad, textCol) : textCol;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor(...muted);
    doc.text(label + ":", 25, y);
    doc.setTextColor(...col);
    const truncated = clean.length > 62 ? clean.substring(0, 59) + "..." : clean;
    doc.text(truncated, 68, y);
    y += 6.5;
  }

  function pdfDivider() {
    doc.setDrawColor(30, 45, 65);
    doc.setLineWidth(0.2);
    doc.line(20, y, 190, y);
    y += 7;
  }

  pdfSection("HTTP Security Headers  -  Layer 7");
  pdfRow("HSTS",               currentData.headers.hsts);
  pdfRow("CSP",                currentData.headers.csp);
  pdfRow("X-Frame-Options",    currentData.headers.xframe);
  pdfRow("X-Content-Type",     currentData.headers.xcontent);
  pdfRow("Referrer-Policy",    currentData.headers.referrer);
  pdfRow("Permissions-Policy", currentData.headers.permissions);
  pdfRow("Server String",      currentData.headers.server,    false);
  pdfRow("Powered By",         currentData.headers.poweredBy, false);

  pdfDivider();

  pdfSection("DNS Infrastructure  -  Layer 4 / 7");
  pdfRow("SPF validation", currentData.dns.spf);
  pdfRow("DMARC state",    currentData.dns.dmarc);
  pdfRow("MX Routing",     currentData.dns.mx);
  pdfRow("NS Records",     currentData.dns.ns,  false);
  pdfRow("Resolved IP",    currentData.dns.ip,  false);

  pdfDivider();

  pdfSection("SSL / TLS Cryptography");
  pdfRow("Active Protocol", currentData.ssl.protocol, false);
  pdfRow("Labs Grade",      currentData.ssl.grade,    false);
  pdfRow("Expiration",      currentData.ssl.expiry,   false);

  pdfDivider();

  if (currentData.ip) {
    pdfSection("Server Geolocation Metadata");
    pdfRow("City Location", currentData.ip.city,    false);
    pdfRow("Country",       currentData.ip.country, false);
    pdfRow("Region State",  currentData.ip.region,  false);
    pdfRow("ASN / Org",     currentData.ip.org,     false);
    pdfDivider();
  }

  pdfSection("Security Extras & Assets");
  pdfRow("robots.txt",   currentData.extras && currentData.extras.robots      ? "[OK] Present" : "[!] Not Found");
  pdfRow("security.txt", currentData.extras && currentData.extras.securityTxt ? "[OK] Present" : "[!] Not Found");
  pdfRow("HTTP Status",  currentData.httpStatus ? String(currentData.httpStatus) : "No response", false);

  doc.setFillColor(...panel);
  doc.rect(0, 283, 210, 14, "F");
  doc.setFontSize(7.5);
  doc.setTextColor(...muted);
  doc.text("Samuel Cedilla Sanchez  |  samuelcedillasanchez.com  |  TFC ASIR", 20, 291);
  doc.setTextColor(...accent);
  doc.text("Edge Security Auditor Node", 152, 291);

  doc.save("Audit_" + currentData.domain + ".pdf");
}
