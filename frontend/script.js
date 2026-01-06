/**
 * Digital Signature System - Frontend
 * Tương tác với API backend
 */

const API_BASE = 'http://localhost:8000';

// ==================== STATE ====================
const state = {
    signFile: null,
    privateKey: null,
    verifyFile: null,
    signature: null,
    publicKey: null,  // Public key for verification
    // PDF Standard Signing
    pdfSignFile: null,
    certificate: null,
    pdfVerifyFile: null
};

// ==================== DOM ELEMENTS ====================
const elements = {
    // Sign
    signFileZone: document.getElementById('signFileZone'),
    signFileInput: document.getElementById('signFileInput'),
    signFileInfo: document.getElementById('signFileInfo'),
    signFileName: document.getElementById('signFileName'),
    privateKeyZone: document.getElementById('privateKeyZone'),
    privateKeyInput: document.getElementById('privateKeyInput'),
    privateKeyInfo: document.getElementById('privateKeyInfo'),
    privateKeyName: document.getElementById('privateKeyName'),
    signBtn: document.getElementById('signBtn'),
    signResult: document.getElementById('signResult'),

    // Verify
    verifyFileZone: document.getElementById('verifyFileZone'),
    verifyFileInput: document.getElementById('verifyFileInput'),
    verifyFileInfo: document.getElementById('verifyFileInfo'),
    verifyFileName: document.getElementById('verifyFileName'),
    signatureZone: document.getElementById('signatureZone'),
    signatureInput: document.getElementById('signatureInput'),
    signatureInfo: document.getElementById('signatureInfo'),
    signatureName: document.getElementById('signatureName'),
    publicKeyZone: document.getElementById('publicKeyZone'),
    publicKeyInput: document.getElementById('publicKeyInput'),
    publicKeyInfo: document.getElementById('publicKeyInfo'),
    publicKeyName: document.getElementById('publicKeyName'),
    verifyBtn: document.getElementById('verifyBtn'),
    verifyResult: document.getElementById('verifyResult'),

    // Generate
    generateForm: document.getElementById('generateForm'),
    generateResult: document.getElementById('generateResult'),


    // PDF Standard Signing
    pdfSignFileZone: document.getElementById('pdfSignFileZone'),
    pdfSignFileInput: document.getElementById('pdfSignFileInput'),
    pdfSignFileInfo: document.getElementById('pdfSignFileInfo'),
    pdfSignFileName: document.getElementById('pdfSignFileName'),
    certificateZone: document.getElementById('certificateZone'),
    certificateInput: document.getElementById('certificateInput'),
    certificateInfo: document.getElementById('certificateInfo'),
    certificateName: document.getElementById('certificateName'),
    certPassword: document.getElementById('certPassword'),
    signPdfBtn: document.getElementById('signPdfBtn'),
    signPdfResult: document.getElementById('signPdfResult'),
    pdfVerifyZone: document.getElementById('pdfVerifyZone'),
    pdfVerifyInput: document.getElementById('pdfVerifyInput'),
    pdfVerifyInfo: document.getElementById('pdfVerifyInfo'),
    pdfVerifyName: document.getElementById('pdfVerifyName'),
    verifyPdfBtn: document.getElementById('verifyPdfBtn'),
    verifyPdfResult: document.getElementById('verifyPdfResult'),
    signatureDetails: document.getElementById('signatureDetails'),
    signatureList: document.getElementById('signatureList'),

    // UI
    loadingSpinner: document.getElementById('loadingSpinner'),
    mainNav: document.getElementById('mainNav')
};

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', () => {
    initDropZones();
    initPdfDropZones();
    initNavigation();
    initForms();
});

// ==================== NAVIGATION ====================
function initNavigation() {
    elements.mainNav.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = link.dataset.tab;

            // Update active
            elements.mainNav.querySelectorAll('.nav-link').forEach(l =>
                l.classList.remove('active'));
            link.classList.add('active');

            // Show/hide tabs
            document.querySelectorAll('.tab-content').forEach(tab =>
                tab.classList.add('d-none'));
            document.getElementById(`${tabId}-tab`).classList.remove('d-none');
        });
    });
}

// ==================== DROP ZONES ====================
function initDropZones() {
    const zones = [
        { zone: elements.signFileZone, input: elements.signFileInput, handler: handleSignFile },
        { zone: elements.privateKeyZone, input: elements.privateKeyInput, handler: handlePrivateKey },
        { zone: elements.verifyFileZone, input: elements.verifyFileInput, handler: handleVerifyFile },
        { zone: elements.signatureZone, input: elements.signatureInput, handler: handleSignature },
        { zone: elements.publicKeyZone, input: elements.publicKeyInput, handler: handlePublicKey }
    ];

    zones.forEach(({ zone, input, handler }) => {
        zone.addEventListener('click', () => input.click());

        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.classList.add('dragover');
        });

        zone.addEventListener('dragleave', () => {
            zone.classList.remove('dragover');
        });

        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('dragover');
            if (e.dataTransfer.files[0]) handler(e.dataTransfer.files[0]);
        });

        input.addEventListener('change', () => {
            if (input.files[0]) handler(input.files[0]);
        });
    });
}

function handleSignFile(file) {
    state.signFile = file;
    elements.signFileZone.classList.add('has-file');
    elements.signFileName.textContent = file.name;
    elements.signFileInfo.classList.add('show');
    updateSignButton();
}

function handlePrivateKey(file) {
    state.privateKey = file;
    elements.privateKeyZone.classList.add('has-file');
    elements.privateKeyName.textContent = file.name;
    elements.privateKeyInfo.classList.add('show');
    updateSignButton();
}

function handleVerifyFile(file) {
    state.verifyFile = file;
    elements.verifyFileZone.classList.add('has-file');
    elements.verifyFileName.textContent = file.name;
    elements.verifyFileInfo.classList.add('show');
    updateVerifyButton();
}

function handleSignature(file) {
    state.signature = file;
    elements.signatureZone.classList.add('has-file');
    elements.signatureName.textContent = file.name;
    elements.signatureInfo.classList.add('show');
    updateVerifyButton();
}

function handlePublicKey(file) {
    state.publicKey = file;
    elements.publicKeyZone.classList.add('has-file');
    elements.publicKeyName.textContent = file.name;
    elements.publicKeyInfo.classList.add('show');
    updateVerifyButton();
}

function updateSignButton() {
    elements.signBtn.disabled = !(state.signFile && state.privateKey);
}

function updateVerifyButton() {
    const hasAll = state.verifyFile && state.signature && state.publicKey;
    elements.verifyBtn.disabled = !hasAll;
}

// ==================== FORMS ====================
function initForms() {
    elements.signBtn.addEventListener('click', signDocument);
    elements.verifyBtn.addEventListener('click', verifyDocument);
    elements.generateForm.addEventListener('submit', generateKeys);

    // PDF Standard Signing
    elements.signPdfBtn.addEventListener('click', signPdfStandard);
    elements.verifyPdfBtn.addEventListener('click', verifyPdfStandard);

    // Generate Certificate
    const genCertBtn = document.getElementById('genCertBtn');
    if (genCertBtn) {
        genCertBtn.addEventListener('click', generateCertificate);
    }
}

// ==================== API CALLS ====================
async function signDocument() {
    showLoading(true);
    hideResult(elements.signResult);

    try {
        const formData = new FormData();
        formData.append('file', state.signFile);
        formData.append('private_key', state.privateKey);

        const response = await fetch(`${API_BASE}/sign`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Signing failed');
        }

        // Download signature
        const blob = await response.blob();
        downloadFile(blob, `${state.signFile.name}.sig`);

        showResult(elements.signResult, true,
            `<i class="bi bi-check-circle me-2"></i>Ký thành công! File chữ ký đã tải về.`);

    } catch (error) {
        showResult(elements.signResult, false,
            `<i class="bi bi-exclamation-circle me-2"></i>${error.message}`);
    } finally {
        showLoading(false);
    }
}

async function verifyDocument() {
    showLoading(true);
    hideResult(elements.verifyResult);

    try {
        const formData = new FormData();
        formData.append('file', state.verifyFile);
        formData.append('signature', state.signature);
        formData.append('public_key_file', state.publicKey);

        const response = await fetch(`${API_BASE}/verify`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Verification failed');
        }

        const result = await response.json();

        if (result.valid) {
            showResult(elements.verifyResult, true,
                `<i class="bi bi-shield-check me-2"></i>${result.message}`);
        } else {
            showResult(elements.verifyResult, false,
                `<i class="bi bi-shield-x me-2"></i>${result.message}`);
        }

    } catch (error) {
        showResult(elements.verifyResult, false,
            `<i class="bi bi-exclamation-circle me-2"></i>${error.message}`);
    } finally {
        showLoading(false);
    }
}

async function generateKeys(e) {
    e.preventDefault();
    showLoading(true);
    hideResult(elements.generateResult);

    const name = document.getElementById('genName').value;
    const department = document.getElementById('genDepartment').value;
    const keySize = document.getElementById('genKeySize').value;

    try {
        const formData = new FormData();
        formData.append('name', name);
        formData.append('department', department);
        formData.append('key_size', keySize);

        const response = await fetch(`${API_BASE}/generate-keys`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Generation failed');
        }

        // Download both keys as JSON
        const data = await response.json();

        // Download private key
        const privateBlob = new Blob([data.private_key], { type: 'application/octet-stream' });
        downloadFile(privateBlob, `${name.replace(/\s+/g, '_')}_private.key`);

        // Download public key
        const publicBlob = new Blob([data.public_key], { type: 'application/octet-stream' });
        downloadFile(publicBlob, `${name.replace(/\s+/g, '_')}_public.key`);

        showResult(elements.generateResult, true,
            `<i class="bi bi-check-circle me-2"></i>Sinh khóa thành công!<br>
            <small class="mt-2 d-block">Private key và Public key đã được tải về.</small>
            <small>Lưu trữ Private key an toàn. Chia sẻ Public key để người khác xác minh chữ ký.</small>`);

        elements.generateForm.reset();

    } catch (error) {
        showResult(elements.generateResult, false,
            `<i class="bi bi-exclamation-circle me-2"></i>${error.message}`);
    } finally {
        showLoading(false);
    }
}

function showResult(element, success, message) {
    element.className = `result-alert show ${success ? 'success' : 'error'}`;
    element.innerHTML = message;
}

function hideResult(element) {
    element.classList.remove('show');
}

function showLoading(show) {
    elements.loadingSpinner.classList.toggle('show', show);
}

function downloadFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(isoString) {
    try {
        const date = new Date(isoString);
        return date.toLocaleString('vi-VN');
    } catch {
        return isoString;
    }
}

// ==================== PDF STANDARD SIGNING ====================
function initPdfDropZones() {
    const pdfZones = [
        { zone: elements.pdfSignFileZone, input: elements.pdfSignFileInput, handler: handlePdfSignFile },
        { zone: elements.certificateZone, input: elements.certificateInput, handler: handleCertificate },
        { zone: elements.pdfVerifyZone, input: elements.pdfVerifyInput, handler: handlePdfVerifyFile }
    ];

    pdfZones.forEach(({ zone, input, handler }) => {
        if (!zone || !input) return;

        zone.addEventListener('click', () => input.click());

        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.classList.add('dragover');
        });

        zone.addEventListener('dragleave', () => {
            zone.classList.remove('dragover');
        });

        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('dragover');
            if (e.dataTransfer.files[0]) handler(e.dataTransfer.files[0]);
        });

        input.addEventListener('change', () => {
            if (input.files[0]) handler(input.files[0]);
        });
    });
}

function handlePdfSignFile(file) {
    state.pdfSignFile = file;
    elements.pdfSignFileZone.classList.add('has-file');
    elements.pdfSignFileName.textContent = file.name;
    elements.pdfSignFileInfo.classList.add('show');
    updateSignPdfButton();
}

function handleCertificate(file) {
    state.certificate = file;
    elements.certificateZone.classList.add('has-file');
    elements.certificateName.textContent = file.name;
    elements.certificateInfo.classList.add('show');
    updateSignPdfButton();
}

function handlePdfVerifyFile(file) {
    state.pdfVerifyFile = file;
    elements.pdfVerifyZone.classList.add('has-file');
    elements.pdfVerifyName.textContent = file.name;
    elements.pdfVerifyInfo.classList.add('show');
    elements.verifyPdfBtn.disabled = false;
}

function updateSignPdfButton() {
    elements.signPdfBtn.disabled = !(state.pdfSignFile && state.certificate);
}

async function signPdfStandard() {
    showLoading(true);
    hideResult(elements.signPdfResult);

    try {
        const formData = new FormData();
        formData.append('pdf_file', state.pdfSignFile);
        formData.append('certificate', state.certificate);
        formData.append('password', elements.certPassword.value || '');

        const response = await fetch(`${API_BASE}/sign-pdf`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'PDF signing failed');
        }

        // Get signer name from header
        const signerName = response.headers.get('X-Signer-Name') || 'Unknown';

        // Download signed PDF
        const blob = await response.blob();
        const filename = state.pdfSignFile.name.replace('.pdf', '_signed.pdf');
        downloadFile(blob, filename);

        showResult(elements.signPdfResult, true,
            `<i class="bi bi-check-circle me-2"></i>Ký PDF thành công!<br>
            <small class="mt-2 d-block">Người ký: <strong>${escapeHtml(signerName)}</strong></small>
            <small>File PDF đã ký được tải về.</small>`);

    } catch (error) {
        showResult(elements.signPdfResult, false,
            `<i class="bi bi-exclamation-circle me-2"></i>${error.message}`);
    } finally {
        showLoading(false);
    }
}

async function verifyPdfStandard() {
    showLoading(true);
    hideResult(elements.verifyPdfResult);
    elements.signatureDetails.classList.add('d-none');

    try {
        const formData = new FormData();
        formData.append('pdf_file', state.pdfVerifyFile);

        const response = await fetch(`${API_BASE}/verify-pdf`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'PDF verification failed');
        }

        const result = await response.json();

        if (!result.has_signatures) {
            showResult(elements.verifyPdfResult, false,
                `<i class="bi bi-info-circle me-2"></i>${result.message}`);
        } else if (result.all_valid) {
            showResult(elements.verifyPdfResult, true,
                `<i class="bi bi-shield-check me-2"></i>${result.message}`);
        } else {
            showResult(elements.verifyPdfResult, false,
                `<i class="bi bi-shield-x me-2"></i>${result.message}`);
        }

        // Show signature details
        if (result.signatures && result.signatures.length > 0) {
            elements.signatureDetails.classList.remove('d-none');
            elements.signatureList.innerHTML = result.signatures.map((sig, i) => `
                <div class="card mb-2" style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);">
                    <div class="card-body py-2 px-3">
                        <div class="d-flex justify-content-between align-items-center">
                            <span>
                                <i class="bi ${sig.valid ? 'bi-check-circle text-success' : 'bi-x-circle text-danger'} me-2"></i>
                                <strong>${escapeHtml(sig.signer)}</strong>
                                ${sig.organization ? `<span class="text-muted"> - ${escapeHtml(sig.organization)}</span>` : ''}
                            </span>
                            <small class="text-muted">${sig.signing_time ? formatDate(sig.signing_time) : 'N/A'}</small>
                        </div>
                        ${sig.reason ? `<small class="text-muted d-block">Lý do: ${escapeHtml(sig.reason)}</small>` : ''}
                        ${sig.location ? `<small class="text-muted d-block">Vị trí: ${escapeHtml(sig.location)}</small>` : ''}
                    </div>
                </div>
            `).join('');
        }

    } catch (error) {
        showResult(elements.verifyPdfResult, false,
            `<i class="bi bi-exclamation-circle me-2"></i>${error.message}`);
    } finally {
        showLoading(false);
    }
}

async function generateCertificate() {
    const nameInput = document.getElementById('genCertName');
    const orgInput = document.getElementById('genCertOrg');
    const passwordInput = document.getElementById('genCertPassword');

    const name = nameInput.value.trim();
    if (!name) {
        alert('Vui lòng nhập tên của bạn');
        nameInput.focus();
        return;
    }

    const password = passwordInput.value.trim();
    if (!password || password.length < 4) {
        alert('Mật khẩu phải có ít nhất 4 ký tự');
        passwordInput.focus();
        return;
    }

    showLoading(true);

    try {
        const formData = new FormData();
        formData.append('name', name);
        formData.append('organization', orgInput.value.trim() || 'Test Organization');
        formData.append('password', password);

        const response = await fetch(`${API_BASE}/generate-certificate`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Certificate generation failed');
        }

        // Download certificate
        const blob = await response.blob();
        const filename = `${name.replace(/\s+/g, '_')}_certificate.pfx`;
        downloadFile(blob, filename);

        alert(`✓ Certificate đã được tạo và tải về!\n\nTên file: ${filename}\nMật khẩu: ${password}\n\nHãy upload file này vào ô Certificate bên trên.`);

        // Clear inputs
        nameInput.value = '';
        orgInput.value = '';
        passwordInput.value = '';

    } catch (error) {
        alert(`Lỗi: ${error.message}`);
    } finally {
        showLoading(false);
    }
}
