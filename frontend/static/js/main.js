/**
 * GhostPixel - Client-side Controller & UI Interactions
 * Secure Image Communication Using AES-256-GCM and LSB Steganography
 */

document.addEventListener("DOMContentLoaded", () => {
    initGlobalHelpers();
    if (document.getElementById("encode-form")) initEncodeModule();
    if (document.getElementById("decode-form")) initDecodeModule();
    if (document.getElementById("performance-runner")) initPerformanceModule();
    if (document.getElementById("lsb-interactive-demo")) initLsbDemo();
});

// ==========================================
// GLOBAL HELPERS
// ==========================================
function initGlobalHelpers() {
    // Password toggle triggers
    document.querySelectorAll(".input-btn-toggle").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            const input = document.getElementById(targetId);
            if (!input) return;
            const isPassword = input.getAttribute("type") === "password";
            input.setAttribute("type", isPassword ? "text" : "password");
            btn.innerHTML = isPassword ? getEyeSlashIcon() : getEyeIcon();
        });
    });

    // Mobile nav toggle
    const navToggle = document.getElementById("nav-toggle");
    const navLinks = document.querySelector(".nav-links");
    if (navToggle && navLinks) {
        navToggle.addEventListener("click", () => {
            navLinks.classList.toggle("nav-open");
        });
    }
}

function getEyeIcon() {
    return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
}

function getEyeSlashIcon() {
    return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
}

function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function copyToClipboard(text, btnElement) {
    navigator.clipboard.writeText(text).then(() => {
        const originalHtml = btnElement.innerHTML;
        btnElement.innerHTML = `<span>Copied!</span>`;
        btnElement.classList.add("btn-success");
        setTimeout(() => {
            btnElement.innerHTML = originalHtml;
            btnElement.classList.remove("btn-success");
        }, 2000);
    }).catch(err => {
        alert("Failed to copy to clipboard: " + err);
    });
}

// ==========================================
// SENDER / ENCODE MODULE
// ==========================================
function initEncodeModule() {
    const messageInput = document.getElementById("secret-message");
    const charCountEl = document.getElementById("char-count");
    const passwordInput = document.getElementById("encode-password");
    const strengthBar = document.getElementById("strength-bar-fill");
    const strengthText = document.getElementById("strength-text");
    const fileInput = document.getElementById("cover-image-input");
    const dropzone = document.getElementById("cover-dropzone");
    const previewContainer = document.getElementById("cover-preview-container");
    const previewImg = document.getElementById("cover-preview");
    const capacityMeter = document.getElementById("capacity-meter");
    const encodeBtn = document.getElementById("btn-encode");
    const errorAlert = document.getElementById("encode-error");
    const resultsPanel = document.getElementById("encode-results");

    let selectedFile = null;

    // Character counter
    messageInput.addEventListener("input", () => {
        const count = messageInput.value.length;
        charCountEl.textContent = `${count} character${count === 1 ? "" : "s"}`;
        triggerCapacityCheck();
    });

    // Preset message buttons
    document.querySelectorAll(".btn-preset-msg").forEach(btn => {
        btn.addEventListener("click", () => {
            const preset = btn.getAttribute("data-preset");
            if (preset === "brief") {
                messageInput.value = "OPERATION GHOSTPIXEL: Primary rendezvous point confirmed at Vector Alpha. Transmit telemetry via secure cryptographic channel.";
            } else if (preset === "geo") {
                messageInput.value = "CLASSIFIED COORDINATES:\nLatitude: 37°46'29.6\"N\nLongitude: 122°25'09.8\"W\nElevation: 124m\nKey: AES-256 authenticated.";
            } else if (preset === "unicode") {
                messageInput.value = "Multi-language & Emojis Test:\n🛡️ 🔐 🕵️ 🚀 🔒 🌐 零一二三\nArabic: سر أمني مشفر\nSpecial: !@#$%^&*()_+=-~`{}[]|:;'<>,.?/";
            }
            messageInput.dispatchEvent(new Event("input"));
        });
    });

    // Password strength check
    passwordInput.addEventListener("input", async () => {
        const pwd = passwordInput.value;
        if (!pwd) {
            strengthBar.style.width = "0%";
            strengthText.textContent = "Strength: None";
            return;
        }

        try {
            const res = await fetch("/api/validate-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: pwd })
            });
            const data = await res.json();
            if (data.success) {
                const evalData = data.evaluation;
                const pct = Math.min(100, (evalData.score / 5) * 100);
                strengthBar.style.width = `${pct}%`;
                
                if (evalData.score <= 1) {
                    strengthBar.style.backgroundColor = "var(--accent-red)";
                } else if (evalData.score <= 3) {
                    strengthBar.style.backgroundColor = "var(--accent-amber)";
                } else {
                    strengthBar.style.backgroundColor = "var(--accent-green)";
                }
                strengthText.textContent = `Strength: ${evalData.label}`;
            }
        } catch (e) {
            console.error("Password check error", e);
        }
    });

    // Dropzone drag-and-drop
    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length) {
            handleImageFile(e.dataTransfer.files[0]);
        }
    });
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length) {
            handleImageFile(fileInput.files[0]);
        }
    });

    // Sample Image click triggers
    document.querySelectorAll(".btn-select-sample").forEach(btn => {
        btn.addEventListener("click", async () => {
            const sampleUrl = btn.getAttribute("data-sample-url");
            try {
                const response = await fetch(sampleUrl);
                const blob = await response.blob();
                const filename = sampleUrl.substring(sampleUrl.lastIndexOf('/') + 1);
                const file = new File([blob], filename, { type: "image/png" });
                handleImageFile(file);
            } catch (err) {
                showError("Failed to load sample image: " + err);
            }
        });
    });

    function handleImageFile(file) {
        const validTypes = ["image/png", "image/bmp", "image/x-ms-bmp"];
        if (!validTypes.includes(file.type) && !file.name.toLowerCase().endsWith(".png") && !file.name.toLowerCase().endsWith(".bmp")) {
            showError("Unsupported format. Please upload a PNG or BMP image.");
            return;
        }

        selectedFile = file;
        hideError();

        // Image Preview
        const reader = new FileReader();
        reader.onload = (e) => {
            previewImg.src = e.target.result;
            previewContainer.classList.remove("hidden");
            triggerCapacityCheck();
        };
        reader.readAsDataURL(file);
    }

    async function triggerCapacityCheck() {
        if (!selectedFile) return;

        const formData = new FormData();
        formData.append("image", selectedFile);
        formData.append("message", messageInput.value);

        try {
            const res = await fetch("/api/check-capacity", {
                method: "POST",
                body: formData
            });
            const data = await res.json();
            if (data.success) {
                renderCapacity(data);
                hideError();
            } else {
                showError(data.error);
            }
        } catch (err) {
            console.error("Capacity check failed", err);
        }
    }

    function renderCapacity(data) {
        capacityMeter.classList.remove("hidden");
        const cap = data.capacity;
        
        document.getElementById("cap-dimensions").textContent = `${data.width} × ${data.height} px`;
        document.getElementById("cap-format").textContent = data.format;
        document.getElementById("cap-file-size").textContent = data.file_size_formatted;
        document.getElementById("cap-usable").textContent = cap.formatted_usable;
        document.getElementById("cap-required").textContent = cap.formatted_required;
        document.getElementById("cap-available").textContent = cap.formatted_available;
        document.getElementById("cap-utilization").textContent = `${cap.utilization_pct}%`;

        const fillBar = document.getElementById("cap-bar-fill");
        fillBar.style.width = `${Math.min(100, cap.utilization_pct)}%`;

        if (!cap.has_capacity) {
            fillBar.style.background = "var(--accent-red)";
            showError(`Insufficient Image Capacity! The image can hold ${cap.formatted_usable}, but the message requires ${cap.formatted_required}. Please select a larger image or shorten the message.`);
            encodeBtn.disabled = true;
        } else {
            fillBar.style.background = cap.utilization_pct > 80 ? "var(--accent-amber)" : "var(--gradient-cyber)";
            encodeBtn.disabled = false;
        }
    }

    function showError(msg) {
        errorAlert.textContent = msg;
        errorAlert.classList.remove("hidden");
    }

    function hideError() {
        errorAlert.classList.add("hidden");
    }

    // Submit / Encode action
    document.getElementById("encode-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        hideError();

        const message = messageInput.value.trim();
        const password = passwordInput.value;

        if (!message) {
            showError("Please enter a secret message.");
            return;
        }
        if (!password) {
            showError("Please enter an encryption password.");
            return;
        }
        if (!selectedFile) {
            showError("Please select or upload a cover image.");
            return;
        }

        // Disable button & show spinner
        encodeBtn.disabled = true;
        const originalBtnText = encodeBtn.innerHTML;
        encodeBtn.innerHTML = `<span class="spinner"></span> Encrypting & Embedding...`;

        const formData = new FormData();
        formData.append("image", selectedFile);
        formData.append("message", message);
        formData.append("password", password);

        try {
            const res = await fetch("/api/encode", {
                method: "POST",
                body: formData
            });
            const data = await res.json();

            if (data.success) {
                renderEncodeResults(data);
                resultsPanel.classList.remove("hidden");
                resultsPanel.scrollIntoView({ behavior: "smooth" });
            } else {
                showError(data.error || "Encoding failed.");
            }
        } catch (err) {
            showError("Failed to connect to GhostPixel server: " + err.message);
        } finally {
            encodeBtn.disabled = false;
            encodeBtn.innerHTML = originalBtnText;
        }
    });

    function renderEncodeResults(data) {
        document.getElementById("res-cover-img").src = data.cover_preview_url;
        document.getElementById("res-stego-img").src = data.stego_preview_url;
        if (data.diff_preview_url && document.getElementById("res-diff-img")) {
            document.getElementById("res-diff-img").src = data.diff_preview_url;
        }
        
        const dlBtn = document.getElementById("btn-download-stego");
        dlBtn.href = data.download_url;
        dlBtn.setAttribute("download", data.filename);

        // Metrics
        document.getElementById("res-psnr").textContent = `${data.metrics.psnr.psnr_db} dB`;
        document.getElementById("res-ssim").textContent = data.metrics.ssim.ssim;
        document.getElementById("res-time-total").textContent = `${data.metrics.timings.total_processing_ms} ms`;
        document.getElementById("res-time-aes").textContent = `${data.metrics.timings.aes_encryption_ms} ms`;
        document.getElementById("res-time-sha").textContent = `${data.metrics.timings.sha256_generation_ms} ms`;
        document.getElementById("res-time-lsb").textContent = `${data.metrics.timings.lsb_embedding_ms} ms`;

        // Crypto Inspector
        document.getElementById("res-crypto-salt").textContent = data.cryptographic_details.salt_hex;
        document.getElementById("res-crypto-nonce").textContent = data.cryptographic_details.nonce_hex;
        document.getElementById("res-crypto-tag").textContent = data.cryptographic_details.tag_hex;
        document.getElementById("res-crypto-hash").textContent = data.cryptographic_details.sha256_hash_hex;
    }
}

// ==========================================
// RECEIVER / DECODE MODULE
// ==========================================
function initDecodeModule() {
    const fileInput = document.getElementById("stego-image-input");
    const dropzone = document.getElementById("stego-dropzone");
    const previewContainer = document.getElementById("stego-preview-container");
    const previewImg = document.getElementById("stego-preview");
    const extractBtn = document.getElementById("btn-extract-verify");
    const errorAlert = document.getElementById("decode-error");
    
    const integrityCard = document.getElementById("integrity-verification-card");
    const passwordSection = document.getElementById("decode-password-section");
    const passwordInput = document.getElementById("decode-password");
    const decryptBtn = document.getElementById("btn-decrypt");
    const resultCard = document.getElementById("decrypt-result-card");
    const recoveredMessageEl = document.getElementById("recovered-message");
    const copyBtn = document.getElementById("btn-copy-recovered");

    let currentFile = null;
    let currentExtractionId = null;
    let currentPayloadToken = null;

    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length) handleStegoFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length) handleStegoFile(fileInput.files[0]);
    });

    function handleStegoFile(file) {
        currentFile = file;
        hideError();
        resetExtractionState();

        const reader = new FileReader();
        reader.onload = (e) => {
            previewImg.src = e.target.result;
            previewContainer.classList.remove("hidden");
            extractBtn.disabled = false;
        };
        reader.readAsDataURL(file);
    }

    function resetExtractionState() {
        currentExtractionId = null;
        integrityCard.classList.add("hidden");
        passwordSection.classList.add("hidden");
        resultCard.classList.add("hidden");
    }

    function showError(msg) {
        errorAlert.textContent = msg;
        errorAlert.classList.remove("hidden");
    }

    function hideError() {
        errorAlert.classList.add("hidden");
    }

    // Step 1: Extract & Verify Integrity
    extractBtn.addEventListener("click", async () => {
        if (!currentFile) {
            showError("Please upload a stego image first.");
            return;
        }

        hideError();
        extractBtn.disabled = true;
        const origText = extractBtn.innerHTML;
        extractBtn.innerHTML = `<span class="spinner"></span> Extracting & Verifying SHA-256...`;

        const formData = new FormData();
        formData.append("image", currentFile);

        try {
            const res = await fetch("/api/extract-info", {
                method: "POST",
                body: formData
            });
            const data = await res.json();

            if (data.success) {
                currentExtractionId = data.extraction_id;
                currentPayloadToken = data.payload_token || null;
                renderIntegrity(data);
                integrityCard.classList.remove("hidden");
                integrityCard.scrollIntoView({ behavior: "smooth" });

                if (data.integrity.is_valid) {
                    passwordSection.classList.remove("hidden");
                    decryptBtn.disabled = false;
                } else {
                    passwordSection.classList.add("hidden");
                    showError("Warning: Payload integrity verification failed! Data may have been tampered with or corrupted. Decryption is prohibited.");
                }
            } else {
                showError(data.error || "Steganographic extraction failed.");
            }
        } catch (err) {
            showError("Extraction failed: " + err.message);
        } finally {
            extractBtn.disabled = false;
            extractBtn.innerHTML = origText;
        }
    });

    function renderIntegrity(data) {
        const integ = data.integrity;
        const rep = data.report || {};
        const overallBadge = document.getElementById("overall-integrity-badge");
        const statusMsg = document.getElementById("integrity-status-msg");

        if (integ.is_valid) {
            if (overallBadge) {
                overallBadge.className = "badge badge-green";
                overallBadge.textContent = "VERIFIED INTACT";
            }
            statusMsg.className = "alert alert-success mt-2";
            statusMsg.textContent = integ.message || "Integrity verified: Extracted encrypted payload matches original SHA-256 digest perfectly.";

            // Stage 1
            const st1Badge = document.getElementById("stage-extract-badge");
            if (st1Badge) { st1Badge.className = "badge badge-green"; st1Badge.textContent = "SUCCESS"; }
            const envSize = document.getElementById("meta-envelope-size");
            if (envSize && data.payload_info) { envSize.textContent = `${data.payload_info.total_payload_bytes} bytes`; }

            // Stage 2
            const st2Badge = document.getElementById("stage-sha-badge");
            if (st2Badge) { st2Badge.className = "badge badge-green"; st2Badge.textContent = "MATCH"; }
            const shaTime = document.getElementById("meta-sha-time");
            if (shaTime && integ.verification_time_ms) { shaTime.textContent = `${integ.verification_time_ms} ms`; }

            // Stage 3
            const st3Badge = document.getElementById("stage-aes-badge");
            if (st3Badge) { st3Badge.className = "badge badge-purple"; st3Badge.textContent = "AWAITING PASSWORD"; }
            const tagShort = document.getElementById("meta-tag-short");
            if (tagShort && data.payload_info) { tagShort.textContent = `${data.payload_info.tag_hex.substring(0, 12)}...`; }

            // Stage 4
            const st4Badge = document.getElementById("stage-overall-badge");
            if (st4Badge) { st4Badge.className = "badge badge-cyan"; st4Badge.textContent = "INTACT"; }
        } else {
            if (overallBadge) {
                overallBadge.className = "badge badge-red";
                overallBadge.textContent = "TAMPERED / MISMATCH";
            }
            statusMsg.className = "alert alert-danger mt-2";
            statusMsg.textContent = integ.message || "Integrity check failed: Extracted payload has been modified, corrupted, or tampered with!";

            const st2Badge = document.getElementById("stage-sha-badge");
            if (st2Badge) { st2Badge.className = "badge badge-red"; st2Badge.textContent = "MISMATCH"; }

            const st3Badge = document.getElementById("stage-aes-badge");
            if (st3Badge) { st3Badge.className = "badge badge-red"; st3Badge.textContent = "HALTED"; }

            const st4Badge = document.getElementById("stage-overall-badge");
            if (st4Badge) { st4Badge.className = "badge badge-red"; st4Badge.textContent = "CORRUPTED"; }
        }

        if (document.getElementById("calc-sha-hash")) {
            document.getElementById("calc-sha-hash").textContent = integ.calculated_hash || "-";
        }
        if (document.getElementById("stored-sha-hash")) {
            document.getElementById("stored-sha-hash").textContent = integ.expected_hash || "-";
        }
        if (data.payload_info) {
            document.getElementById("meta-salt").textContent = data.payload_info.salt_hex || "-";
            document.getElementById("meta-nonce").textContent = data.payload_info.nonce_hex || "-";
            document.getElementById("meta-tag").textContent = data.payload_info.tag_hex || "-";
            document.getElementById("meta-ciphertext-size").textContent = `${data.payload_info.ciphertext_bytes} bytes`;
        }
    }

    // Step 2: Decrypt with Password
    decryptBtn.addEventListener("click", async () => {
        const password = passwordInput.value;
        if (!password) {
            showError("Please enter the decryption password.");
            return;
        }

        hideError();
        decryptBtn.disabled = true;
        const origText = decryptBtn.innerHTML;
        decryptBtn.innerHTML = `<span class="spinner"></span> Decrypting & Authenticating...`;

        try {
            const res = await fetch("/api/decrypt", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    extraction_id: currentExtractionId,
                    payload_token: currentPayloadToken,
                    password: password
                })
            });
            const data = await res.json();

            if (data.success) {
                recoveredMessageEl.value = data.decrypted_message;
                document.getElementById("decryption-time").textContent = `${data.decryption_time_ms} ms`;
                resultCard.classList.remove("hidden");
                resultCard.scrollIntoView({ behavior: "smooth" });

                // Update scorecard on successful authentication
                const st3Badge = document.getElementById("stage-aes-badge");
                if (st3Badge) { st3Badge.className = "badge badge-green"; st3Badge.textContent = "AUTHENTICATED"; }
                const st3Details = document.getElementById("stage-aes-details");
                if (st3Details) { st3Details.textContent = "128-bit Tag Verified"; }

                const st4Badge = document.getElementById("stage-overall-badge");
                if (st4Badge) { st4Badge.className = "badge badge-green"; st4Badge.textContent = "SECURE & VERIFIED"; }
                const st4Details = document.getElementById("stage-overall-details");
                if (st4Details) { st4Details.textContent = "Full Pipeline Authenticated"; }
            } else {
                // Update scorecard on authentication failure
                const st3Badge = document.getElementById("stage-aes-badge");
                if (st3Badge) { st3Badge.className = "badge badge-red"; st3Badge.textContent = "AUTH FAILED"; }
                const st3Details = document.getElementById("stage-aes-details");
                if (st3Details) { st3Details.textContent = "Invalid Key / Tag Mismatch"; }

                const st4Badge = document.getElementById("stage-overall-badge");
                if (st4Badge) { st4Badge.className = "badge badge-red"; st4Badge.textContent = "AUTH REJECTED"; }
                const st4Details = document.getElementById("stage-overall-details");
                if (st4Details) { st4Details.textContent = "Decryption Prohibited"; }

                showError(data.error || "Decryption failed. Please verify your password.");
            }
        } catch (err) {
            showError("Decryption request failed: " + err.message);
        } finally {
            decryptBtn.disabled = false;
            decryptBtn.innerHTML = origText;
        }
    });

    // Copy recovered message button
    copyBtn.addEventListener("click", () => {
        copyToClipboard(recoveredMessageEl.value, copyBtn);
    });
}

// ==========================================
// PERFORMANCE EVALUATION MODULE
// ==========================================
function initPerformanceModule() {
    const runBtn = document.getElementById("btn-run-benchmark");
    const testTypeSelect = document.getElementById("bench-test-type");
    const customMsgInput = document.getElementById("bench-custom-message");
    const sampleImgSelect = document.getElementById("bench-sample-image");
    const benchResults = document.getElementById("bench-results-container");

    runBtn.addEventListener("click", async () => {
        runBtn.disabled = true;
        const origText = runBtn.innerHTML;
        runBtn.innerHTML = `<span class="spinner"></span> Running Automated Benchmark...`;

        try {
            const res = await fetch("/api/performance/run-test", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    test_type: testTypeSelect.value,
                    custom_message: customMsgInput.value,
                    sample_image: sampleImgSelect.value
                })
            });
            const data = await res.json();

            if (data.success) {
                renderBenchmarkResults(data);
                benchResults.classList.remove("hidden");
                benchResults.scrollIntoView({ behavior: "smooth" });
            } else {
                alert("Benchmark failed: " + (data.error || "Unknown error"));
            }
        } catch (err) {
            alert("Benchmark failed: " + err.message);
        } finally {
            runBtn.disabled = false;
            runBtn.innerHTML = origText;
        }
    });

    function renderBenchmarkResults(data) {
        // Pipeline metrics
        if (data.pipeline) {
            const p = data.pipeline;
            document.getElementById("bench-psnr").textContent = `${p.metrics.psnr.psnr_db} dB`;
            document.getElementById("bench-ssim").textContent = p.metrics.ssim.ssim;
            document.getElementById("bench-total-time").textContent = `${p.total_time_ms} ms`;
            document.getElementById("bench-cap-util").textContent = `${p.metrics.capacity.utilization_pct}%`;

            // Timings breakdown
            document.getElementById("bench-t-aes-enc").textContent = `${p.timings.aes_encryption_ms} ms`;
            document.getElementById("bench-t-sha-gen").textContent = `${p.timings.sha256_generation_ms} ms`;
            document.getElementById("bench-t-lsb-embed").textContent = `${p.timings.lsb_embedding_ms} ms`;
            document.getElementById("bench-t-lsb-extract").textContent = `${p.timings.lsb_extraction_ms} ms`;
            document.getElementById("bench-t-sha-ver").textContent = `${p.timings.sha256_verification_ms} ms`;
            document.getElementById("bench-t-aes-dec").textContent = `${p.timings.aes_decryption_ms} ms`;

            // Timing bar visualizer
            const total = p.total_time_ms || 1;
            document.getElementById("bar-t-enc").style.width = `${(p.timings.aes_encryption_ms / total) * 100}%`;
            document.getElementById("bar-t-embed").style.width = `${(p.timings.lsb_embedding_ms / total) * 100}%`;
            document.getElementById("bar-t-extract").style.width = `${(p.timings.lsb_extraction_ms / total) * 100}%`;
            document.getElementById("bar-t-dec").style.width = `${(p.timings.aes_decryption_ms / total) * 100}%`;
        }

        // Accuracy Suite
        if (data.accuracy) {
            document.getElementById("bench-accuracy-pct").textContent = `${data.accuracy.recovery_accuracy_pct}%`;
            document.getElementById("bench-accuracy-score").textContent = `${data.accuracy.successfully_recovered} / ${data.accuracy.total_tested} Passed`;
            
            const tbody = document.getElementById("accuracy-table-body");
            tbody.innerHTML = "";
            data.accuracy.results.forEach(row => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>#${row.test_id}</td>
                    <td><code>${row.sample}</code></td>
                    <td>${row.length} chars</td>
                    <td>${row.total_time_ms} ms</td>
                    <td>${row.psnr_db} dB</td>
                    <td>${row.recovered ? '<span class="badge badge-green">Exact Match</span>' : '<span class="badge badge-red">Failed</span>'}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        // Integrity Suite
        if (data.integrity) {
            document.getElementById("bench-integrity-pct").textContent = `${data.integrity.integrity_detection_rate_pct}%`;
            document.getElementById("bench-integrity-score").textContent = `${data.integrity.tampered_detected} / ${data.integrity.total_tampered_tested} Detected`;

            const tbody = document.getElementById("integrity-table-body");
            tbody.innerHTML = "";
            data.integrity.test_cases.forEach((tc, idx) => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>#${idx + 1}</td>
                    <td><strong>${tc.name}</strong><br><small style="color:var(--text-muted)">${tc.description}</small></td>
                    <td>${tc.expected_outcome}</td>
                    <td>${tc.actual_outcome}</td>
                    <td>${tc.success ? '<span class="badge badge-green">Correctly Handled</span>' : '<span class="badge badge-red">Failed</span>'}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    }
}

// ==========================================
// SECURITY / INTERACTIVE LSB DEMO
// ==========================================
function initLsbDemo() {
    const bitBtns = document.querySelectorAll(".demo-bit");
    const byteValEl = document.getElementById("demo-byte-val");
    const byteBinaryEl = document.getElementById("demo-binary-str");
    const previewColorBox = document.getElementById("demo-color-box");
    const lsbToggleBtn = document.getElementById("demo-toggle-lsb");

    let currentByte = 214; // Default starting byte: 11010110 (RGB Blue component)

    function updateDemoDisplay() {
        const binStr = currentByte.toString(2).padStart(8, "0");
        byteValEl.textContent = currentByte;
        byteBinaryEl.textContent = binStr;
        previewColorBox.style.backgroundColor = `rgb(30, 80, ${currentByte})`;

        bitBtns.forEach((btn, idx) => {
            const bit = binStr[idx];
            btn.textContent = bit;
            btn.className = bit === "1" ? "demo-bit active" : "demo-bit";
            if (idx === 7) btn.classList.add("lsb-highlight");
        });
    }

    if (lsbToggleBtn) {
        lsbToggleBtn.addEventListener("click", () => {
            currentByte ^= 1; // Toggle LSB
            updateDemoDisplay();
        });
    }

    bitBtns.forEach((btn, idx) => {
        btn.addEventListener("click", () => {
            currentByte ^= (1 << (7 - idx));
            updateDemoDisplay();
        });
    });

    updateDemoDisplay();
}

