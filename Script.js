const API_URL = "http://127.0.0.1:5000";

let riskChart = null;
let typeChart = null;

// =====================================================
// LOGIN
// =====================================================

function login() {
    const username = document.getElementById("username")?.value.trim();
    const password = document.getElementById("password")?.value.trim();

    if (!username || !password) {
        alert("Please enter username and password.");
        return;
    }

    localStorage.setItem("fraudUser", username);
    showApp();
}

function showApp() {
    document.getElementById("loginPage")?.classList.add("hidden");
    document.getElementById("app")?.classList.remove("hidden");

    updateDashboard();
    displayHistory();
    createCharts();
    testBackend();
}

function logout() {
    localStorage.removeItem("fraudUser");

    document.getElementById("app")?.classList.add("hidden");
    document.getElementById("loginPage")?.classList.remove("hidden");
}

// =====================================================
// NAVIGATION
// =====================================================

function showSection(sectionName) {
    document.querySelectorAll(".section").forEach(section => {
        section.classList.add("hidden");
    });

    const section = document.getElementById(sectionName);

    if (section) {
        section.classList.remove("hidden");
    }

    updateDashboard();
    displayHistory();
    createCharts();
}

// =====================================================
// GENERIC API REQUEST
// =====================================================

async function sendRequest(endpoint, body) {
    const response = await fetch(API_URL + endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "Request failed");
    }

    return data;
}

// =====================================================
// MESSAGE DETECTION
// =====================================================

async function checkMessage() {
    const input = document.getElementById("messageInput");
    const result = document.getElementById("messageResult");

    const message = input?.value.trim();

    if (!message) {
        result.innerHTML = "⚠️ Please enter a message.";
        return;
    }

    result.innerHTML = "🔄 Analyzing message...";

    try {
        const data = await sendRequest(
            "/api/analyze-message",
            { message }
        );

        showResult(result, data, "Message");

    } catch (error) {
        console.error(error);
        result.innerHTML =
            "❌ Unable to connect to backend. Make sure Flask is running.";
    }
}

// =====================================================
// EMAIL DETECTION
// =====================================================

async function checkEmail() {
    const input = document.getElementById("emailInput");
    const result = document.getElementById("emailResult");

    const email = input?.value.trim();

    if (!email) {
        result.innerHTML = "⚠️ Please paste an email.";
        return;
    }

    result.innerHTML = "🔄 Analyzing email...";

    try {
        const data = await sendRequest(
            "/api/analyze-email",
            { email }
        );

        showResult(result, data, "Email");

    } catch (error) {
        console.error(error);
        result.innerHTML =
            "❌ Unable to connect to backend. Make sure Flask is running.";
    }
}

// =====================================================
// URL DETECTION
// =====================================================

async function checkURL() {
    const input = document.getElementById("urlInput");
    const result = document.getElementById("urlResult");

    const url = input?.value.trim();

    if (!url) {
        result.innerHTML = "⚠️ Please enter a URL.";
        return;
    }

    result.innerHTML = "🔄 Analyzing URL...";

    try {
        const data = await sendRequest(
            "/api/analyze-url",
            { url }
        );

        showResult(result, data, "URL");

    } catch (error) {
        console.error(error);
        result.innerHTML =
            "❌ Unable to connect to backend. Make sure Flask is running.";
    }
}

// =====================================================
// TRANSACTION DETECTION
// =====================================================

async function checkTransaction() {
    const input = document.getElementById("amountInput");
    const result = document.getElementById("transactionResult");

    const amount = Number(input?.value);

    if (!amount || amount <= 0) {
        result.innerHTML = "⚠️ Enter a valid amount.";
        return;
    }

    result.innerHTML = "🔄 Analyzing transaction...";

    try {
        const data = await sendRequest(
            "/api/analyze-transaction",
            { amount }
        );

        showResult(result, data, "Transaction");

    } catch (error) {
        console.error(error);
        result.innerHTML =
            "❌ Unable to connect to backend. Make sure Flask is running.";
    }
}

// =====================================================
// DISPLAY RESULT
// =====================================================

function showResult(element, data, type) {
    const risk = Math.max(
        0,
        Math.min(100, Number(data.risk_score) || 0)
    );

    let level = "LOW";

    if (risk >= 60) {
        level = "HIGH";
    } else if (risk >= 30) {
        level = "MEDIUM";
    }

    const reasons =
        data.reasons && data.reasons.length
            ? data.reasons
                .map(reason => `• ${escapeHTML(reason)}`)
                .join("<br>")
            : "No major suspicious indicators detected.";

    let recommendation;

    if (risk >= 60) {
        recommendation =
            "🚨 Do not proceed. Verify the source independently.";
    } else if (risk >= 30) {
        recommendation =
            "⚠️ Verify the information before proceeding.";
    } else {
        recommendation =
            "✅ No major suspicious pattern detected.";
    }

    element.innerHTML = `
        <div class="result-box">

            <h3>${escapeHTML(data.status)}</h3>

            <div class="risk-meter">
                <div
                    class="risk-fill"
                    style="width:${risk}%">
                </div>
            </div>

            <strong>Fraud Risk: ${risk}%</strong>

            <br><br>

            Risk Level:
            <strong>${level}</strong>

            <br><br>

            <strong>AI Analysis</strong>

            <br><br>

            ${reasons}

            <br><br>

            <strong>Recommendation</strong>

            <br>

            ${recommendation}

            <br><br>

            <button
                type="button"
                onclick='downloadReport(
                    ${JSON.stringify(data)},
                    ${JSON.stringify(type)}
                )'>
                📝 Download Report
            </button>

        </div>
    `;

    if (risk >= 60) {
        alert(
            "🚨 HIGH FRAUD RISK DETECTED!\n\n" +
            `Risk Score: ${risk}%`
        );
    }

    saveHistory(type, data, level);
    updateDashboard();
    displayHistory();
    createCharts();
}

// =====================================================
// HISTORY
// =====================================================

function saveHistory(type, data, level) {
    let history = getHistory();

    history.unshift({
        type,
        status: data.status,
        risk: Number(data.risk_score) || 0,
        level,
        reasons: data.reasons || [],
        time: new Date().toLocaleString()
    });

    history = history.slice(0, 50);

    localStorage.setItem(
        "fraudHistory",
        JSON.stringify(history)
    );
}

function getHistory() {
    try {
        return JSON.parse(
            localStorage.getItem("fraudHistory")
        ) || [];
    } catch {
        return [];
    }
}

function displayHistory() {
    const container =
        document.getElementById("historyList");

    if (!container) return;

    const history = getHistory();

    if (!history.length) {
        container.innerHTML =
            "No detection history yet.";
        return;
    }

    container.innerHTML = history.map(item => `
        <div class="history-item">

            <strong>${escapeHTML(item.type)}</strong>

            <br><br>

            Status:
            <strong>${escapeHTML(item.status)}</strong>

            <br>

            Risk:
            <strong>${item.risk}%</strong>

            <br>

            Level:
            <strong>${escapeHTML(item.level)}</strong>

            <br>

            <small>${escapeHTML(item.time)}</small>

            <br><br>

            ${
                item.reasons?.length
                    ? item.reasons
                        .map(escapeHTML)
                        .join(" • ")
                    : "No suspicious indicators"
            }

        </div>
    `).join("");
}

function clearHistory() {
    if (!confirm("Clear all detection history?")) {
        return;
    }

    localStorage.removeItem("fraudHistory");

    updateDashboard();
    displayHistory();
    createCharts();
}

// =====================================================
// DASHBOARD
// =====================================================

function updateDashboard() {
    const history = getHistory();

    let low = 0;
    let medium = 0;
    let high = 0;

    history.forEach(item => {
        if (item.level === "LOW") {
            low++;
        } else if (item.level === "MEDIUM") {
            medium++;
        } else if (item.level === "HIGH") {
            high++;
        }
    });

    const total = document.getElementById("totalScans");
    const safe = document.getElementById("safeScans");
    const warning = document.getElementById("warningScans");
    const highRisk = document.getElementById("highRiskScans");
    const status = document.getElementById("securityStatus");

    if (total) total.innerText = history.length;
    if (safe) safe.innerText = low;
    if (warning) warning.innerText = medium;
    if (highRisk) highRisk.innerText = high;

    if (!status) return;

    if (high > 0) {
        status.innerText =
            "🚨 High Risk Activity Detected";
    } else if (medium > 0) {
        status.innerText =
            "🟡 Suspicious Activity Detected";
    } else {
        status.innerText =
            "🟢 System Secure";
    }
}

// =====================================================
// CHARTS
// =====================================================

function createCharts() {
    if (typeof Chart === "undefined") {
        return;
    }

    const riskCanvas =
        document.getElementById("riskChart");

    const typeCanvas =
        document.getElementById("typeChart");

    if (!riskCanvas || !typeCanvas) {
        return;
    }

    const history = getHistory();

    let low = 0;
    let medium = 0;
    let high = 0;

    let message = 0;
    let url = 0;
    let email = 0;
    let transaction = 0;

    history.forEach(item => {
        if (item.level === "LOW") low++;
        if (item.level === "MEDIUM") medium++;
        if (item.level === "HIGH") high++;

        if (item.type === "Message") message++;
        if (item.type === "URL") url++;
        if (item.type === "Email") email++;
        if (item.type === "Transaction") transaction++;
    });

    if (riskChart) {
        riskChart.destroy();
    }

    if (typeChart) {
        typeChart.destroy();
    }

    riskChart = new Chart(riskCanvas, {
        type: "doughnut",

        data: {
            labels: [
                "Low Risk",
                "Medium Risk",
                "High Risk"
            ],

            datasets: [{
                data: [
                    low,
                    medium,
                    high
                ]
            }]
        },

        options: {
            responsive: true
        }
    });

    typeChart = new Chart(typeCanvas, {
        type: "bar",

        data: {
            labels: [
                "Messages",
                "URLs",
                "Emails",
                "Transactions"
            ],

            datasets: [{
                label: "Scans",

                data: [
                    message,
                    url,
                    email,
                    transaction
                ]
            }]
        },

        options: {
            responsive: true,

            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// =====================================================
// DOWNLOAD REPORT
// =====================================================

function downloadReport(data, type) {
    const risk = Number(data.risk_score) || 0;

    const reasons =
        data.reasons?.length
            ? data.reasons
                .map(reason => "- " + reason)
                .join("\n")
            : "- No suspicious indicators";

    const recommendation =
        risk >= 60
            ? "Do not proceed. Verify the source independently."
            : risk >= 30
                ? "Verify the information before proceeding."
                : "No major suspicious pattern detected.";

    const report = `
FRAUDSHIELD AI
CYBER FRAUD ANALYSIS REPORT
========================================

Detection Type:
${type}

Status:
${data.status}

Fraud Risk:
${risk}%

Date:
${new Date().toLocaleString()}

----------------------------------------
DETECTION REASONS
----------------------------------------

${reasons}

----------------------------------------
RECOMMENDATION
----------------------------------------

${recommendation}

========================================
Generated by FraudShield AI
========================================
`;

    const blob = new Blob(
        [report],
        { type: "text/plain" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "FraudShield_Report.txt";

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}

// =====================================================
// BACKEND TEST
// =====================================================

async function testBackend() {
    try {
        const response =
            await fetch(API_URL + "/api/health");

        const data =
            await response.json();

        console.log(
            "✅ FraudShield Backend:",
            data
        );

    } catch (error) {
        console.error(
            "❌ Backend connection failed:",
            error
        );
    }
}

// =====================================================
// SECURITY HELPER
// =====================================================

function escapeHTML(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// =====================================================
// PAGE LOAD
// =====================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {
        const user =
            localStorage.getItem("fraudUser");

        if (user) {
            showApp();
        }
    }
);
