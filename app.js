// =============================================================
// Secure File Transfer System — Frontend Application Logic
// =============================================================

(function () {
  "use strict";

  // ── State ──────────────────────────────────────────────────
  let currentUser = "";
  let currentPass = "";
  let selectedFile = null;       // File object
  let fileBuffer = null;         // ArrayBuffer of the selected file
  let transferCount = 0;         // Counter for history table rows

  // ── DOM References ─────────────────────────────────────────
  const loginView       = document.getElementById("loginView");
  const dashboardView   = document.getElementById("dashboardView");
  const loginCard       = document.getElementById("loginCard");
  const loginForm       = document.getElementById("loginForm");
  const loginBtn        = document.getElementById("loginBtn");
  const loginStatus     = document.getElementById("loginStatus");
  const usernameInput   = document.getElementById("username");
  const passwordInput   = document.getElementById("password");

  const dashUser        = document.getElementById("dashUser");
  const authUser        = document.getElementById("authUser");
  const disconnectBtn   = document.getElementById("disconnectBtn");

  const dropzone        = document.getElementById("dropzone");
  const fileInput       = document.getElementById("fileInput");
  const fileInfo        = document.getElementById("fileInfo");
  const fileName        = document.getElementById("fileName");
  const fileSize        = document.getElementById("fileSize");
  const fileType        = document.getElementById("fileType");
  const sendBtn         = document.getElementById("sendBtn");

  const progressCard    = document.getElementById("progressCard");
  const progressFill    = document.getElementById("progressFill");
  const integrityCard   = document.getElementById("integrityCard");
  const hashValue       = document.getElementById("hashValue");
  const hashStatus      = document.getElementById("hashStatus");
  const encDetails      = document.getElementById("encDetails");

  const historyBody     = document.getElementById("historyBody");
  const emptyHistory    = document.getElementById("emptyHistory");

  // Step icon & detail elements (indices 0–4)
  const stepIcons   = [0, 1, 2, 3, 4].map(i => document.getElementById("stepIcon" + i));
  const stepDetails = [0, 1, 2, 3, 4].map(i => document.getElementById("stepDetail" + i));
  const stepItems   = document.querySelectorAll(".step");

  // ── Helpers ────────────────────────────────────────────────

  /**
   * Format a byte count into a human-readable string (B / KB / MB / GB).
   */
  function formatSize(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / Math.pow(1024, i);
    return value.toFixed(i === 0 ? 0 : 2) + " " + units[i];
  }

  /**
   * Return a short timestamp string for the history table.
   */
  function timestamp() {
    return new Date().toLocaleString();
  }

  /**
   * Set a step's visual state.
   * @param {number} index  Step index 0–4.
   * @param {"pending"|"success"|"error"} state
   * @param {string} [detail]  Optional detail text.
   */
  function setStep(index, state, detail) {
    const icons = { pending: "⏳", success: "✅", error: "❌" };
    stepIcons[index].textContent = icons[state] || "⏳";
    if (detail) stepDetails[index].textContent = detail;

    // CSS modifier classes
    stepItems[index].classList.remove("step-success", "step-error");
    if (state === "success") stepItems[index].classList.add("step-success");
    if (state === "error")   stepItems[index].classList.add("step-error");
  }

  /**
   * Reset all steps to pending.
   */
  function resetSteps() {
    for (let i = 0; i < 5; i++) {
      setStep(i, "pending", "");
    }
    progressFill.style.width = "0%";
  }

  /**
   * Promise-based delay utility.
   */
  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Show / hide views with a smooth transition.
   */
  function showView(view) {
    loginView.classList.add("hidden");
    dashboardView.classList.add("hidden");
    view.classList.remove("hidden");
  }

  // ── Login ──────────────────────────────────────────────────

  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const user = usernameInput.value.trim();
    const pass = passwordInput.value.trim();
    if (!user || !pass) return;

    // Show loading state
    loginBtn.querySelector(".btn-text").classList.add("hidden");
    loginBtn.querySelector(".btn-spinner").classList.remove("hidden");
    loginBtn.disabled = true;
    loginStatus.textContent = "";
    loginStatus.className = "status-message";

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass }),
      });

      const data = await res.json();

      if (data.success) {
        // Store credentials
        currentUser = user;
        currentPass = pass;

        // Update dashboard
        dashUser.textContent = user;
        authUser.textContent = user;

        // Transition to dashboard
        showView(dashboardView);
      } else {
        // Show error, shake the card
        loginStatus.textContent = data.message || "Authentication failed.";
        loginStatus.className = "status-message text-error";
        loginCard.classList.add("shake");
        setTimeout(() => loginCard.classList.remove("shake"), 500);
      }
    } catch (err) {
      loginStatus.textContent = "Cannot connect to bridge server. Is it running?";
      loginStatus.className = "status-message text-error";
      loginCard.classList.add("shake");
      setTimeout(() => loginCard.classList.remove("shake"), 500);
    } finally {
      // Restore button
      loginBtn.querySelector(".btn-text").classList.remove("hidden");
      loginBtn.querySelector(".btn-spinner").classList.add("hidden");
      loginBtn.disabled = false;
    }
  });

  // ── Disconnect ─────────────────────────────────────────────

  disconnectBtn.addEventListener("click", function () {
    // Clear state
    currentUser = "";
    currentPass = "";
    selectedFile = null;
    fileBuffer = null;
    usernameInput.value = "";
    passwordInput.value = "";
    loginStatus.textContent = "";
    loginStatus.className = "status-message";

    // Reset file transfer UI
    fileInfo.classList.add("hidden");
    sendBtn.disabled = true;
    progressCard.classList.add("hidden");
    integrityCard.classList.add("hidden");
    resetSteps();

    // Show login
    showView(loginView);
  });

  // ── File Selection (click + drag-and-drop) ─────────────────

  dropzone.addEventListener("dragover", function (e) {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", function () {
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", function (e) {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", function () {
    if (fileInput.files.length > 0) {
      handleFile(fileInput.files[0]);
    }
  });

  /**
   * Process a selected file: read it into an ArrayBuffer and show file info.
   */
  function handleFile(file) {
    selectedFile = file;

    fileName.textContent = file.name;
    fileSize.textContent = formatSize(file.size);
    fileType.textContent = file.type || "unknown";
    fileInfo.classList.remove("hidden");

    // Read file into ArrayBuffer for transfer
    const reader = new FileReader();
    reader.onload = function () {
      fileBuffer = reader.result;
      sendBtn.disabled = false;
    };
    reader.onerror = function () {
      fileBuffer = null;
      sendBtn.disabled = true;
    };
    reader.readAsArrayBuffer(file);
  }

  // ── Send Secure File ───────────────────────────────────────

  sendBtn.addEventListener("click", async function () {
    if (!selectedFile || !fileBuffer) return;

    // Disable button, show progress section
    sendBtn.disabled = true;
    progressCard.classList.remove("hidden");
    integrityCard.classList.add("hidden");
    resetSteps();

    // Simulated step-by-step visual pacing (runs in parallel with the API call).
    // Each step is shown as "pending" then upgraded to success with a delay.
    // The actual API response will overwrite the final state.
    const pacePromise = (async () => {
      await delay(500);
      setStep(0, "success", "Connected to server");
      progressFill.style.width = "20%";

      await delay(500);
      setStep(1, "success", "Credentials verified");
      progressFill.style.width = "40%";

      await delay(500);
      setStep(2, "success", "AES-256-CBC ready");
      progressFill.style.width = "60%";

      await delay(500);
      setStep(3, "success", "Sending data…");
      progressFill.style.width = "80%";

      await delay(500);
      setStep(4, "success", "Computing hash…");
      progressFill.style.width = "95%";
    })();

    // The actual API call runs concurrently
    let apiData = null;
    let apiError = null;

    try {
      const res = await fetch("/api/transfer", {
        method: "POST",
        headers: {
          "X-Username": currentUser,
          "X-Password": currentPass,
          "X-Filename": selectedFile.name,
          "Content-Length": fileBuffer.byteLength.toString(),
        },
        body: fileBuffer,
      });

      apiData = await res.json();
    } catch (err) {
      apiError = err;
    }

    // Wait for the visual pacing to finish before applying real results
    await pacePromise;

    // Small extra pause for polish
    await delay(300);

    // ── Apply real results ──────────────────────────────────
    if (apiError) {
      // Network-level failure
      progressFill.style.width = "100%";
      for (let i = 0; i < 5; i++) setStep(i, "error", "");
      setStep(0, "error", "Cannot connect to bridge server");
      addHistoryRow(false, "—", "—", "Network Error");
      sendBtn.disabled = false;
      return;
    }

    const d = apiData;

    if (d.success) {
      // All steps succeeded
      progressFill.style.width = "100%";

      // Step 0 — Connection
      setStep(0, "success",
        "Connected to " + d.connection.server + ":" + d.connection.port);

      // Step 1 — Authentication
      setStep(1, "success",
        "Authenticated via " + d.authentication.method);

      // Step 2 — Encryption
      setStep(2, "success",
        d.encryption.algorithm + " · IV: " + d.encryption.ivHex.substring(0, 16) + "…");

      // Step 3 — Transfer
      setStep(3, "success",
        formatSize(d.transfer.bytesSent) + " sent");

      // Step 4 — Integrity
      setStep(4, "success",
        "SHA-256 hash computed & sent");

      // Show integrity panel
      hashValue.textContent = d.integrity.originalHash;
      hashStatus.textContent = d.integrity.hashSentToServer
        ? "Hash sent to server for verification"
        : "Hash NOT sent to server";
      hashStatus.className = d.integrity.hashSentToServer ? "text-success" : "text-warning";

      // Encryption details
      encDetails.innerHTML = [
        detail("Algorithm", d.encryption.algorithm),
        detail("IV (hex)", d.encryption.ivHex),
        detail("Original Size", formatSize(d.encryption.originalSize)),
        detail("Encrypted Size", formatSize(d.encryption.encryptedSize)),
      ].join("");

      integrityCard.classList.remove("hidden");

      // History row
      addHistoryRow(
        true,
        d.encryption.algorithm,
        "SHA-256 ✅",
        "Success"
      );
    } else {
      // Partial failure — apply each available step
      progressFill.style.width = "100%";

      const stepKeys = ["connection", "authentication", "encryption", "transfer", "integrity"];
      const failedIndex = stepKeys.indexOf(d.failedStep);

      stepKeys.forEach((key, i) => {
        if (d[key]) {
          if (d[key].success) {
            const details = {
              connection:     "Connected to " + (d[key].server || "—") + ":" + (d[key].port || "—"),
              authentication: "Method: " + (d[key].method || "—"),
              encryption:     (d[key].algorithm || "—"),
              transfer:       formatSize(d[key].bytesSent || 0) + " sent",
              integrity:      "Hash computed",
            };
            setStep(i, "success", details[key]);
          } else {
            setStep(i, "error", d.error || "Failed");
          }
        } else if (i === failedIndex) {
          setStep(i, "error", d.error || "Failed");
        } else if (i > failedIndex && failedIndex >= 0) {
          setStep(i, "pending", "Skipped");
        }
      });

      addHistoryRow(
        false,
        d.encryption ? d.encryption.algorithm : "—",
        "—",
        "Failed at " + (d.failedStep || "unknown")
      );
    }

    sendBtn.disabled = false;
  });

  /**
   * Build an HTML string for a single detail item in the integrity panel.
   */
  function detail(label, value) {
    return '<div class="detail-item">' +
      '<span class="detail-label">' + escapeHtml(label) + '</span>' +
      '<span class="detail-value">' + escapeHtml(String(value)) + '</span>' +
      '</div>';
  }

  /**
   * Escape HTML special characters to prevent XSS.
   */
  function escapeHtml(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  // ── History Table ──────────────────────────────────────────

  /**
   * Add a row to the transfer history table.
   * @param {boolean} success     Whether the transfer succeeded.
   * @param {string}  encryption  Encryption algorithm used.
   * @param {string}  integrity   Integrity check result.
   * @param {string}  statusText  Status label.
   */
  function addHistoryRow(success, encryption, integrity, statusText) {
    transferCount++;
    emptyHistory.classList.add("hidden");

    var tr = document.createElement("tr");
    tr.className = success ? "row-success" : "row-error";

    tr.innerHTML =
      "<td>" + transferCount + "</td>" +
      "<td>" + escapeHtml(timestamp()) + "</td>" +
      "<td>" + escapeHtml(selectedFile ? selectedFile.name : "—") + "</td>" +
      "<td>" + escapeHtml(selectedFile ? formatSize(selectedFile.size) : "—") + "</td>" +
      "<td>" + escapeHtml(encryption) + "</td>" +
      "<td>" + escapeHtml(integrity) + "</td>" +
      "<td>" + escapeHtml(statusText) + "</td>";

    historyBody.appendChild(tr);
  }

  // ── Initialization ─────────────────────────────────────────
  // Ensure only the login view is visible on page load.
  showView(loginView);
})();
