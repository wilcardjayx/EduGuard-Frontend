/**
 * EduGuard Auditor — Live Audit Workspace & Remediation Engine
 */

let isDevPatchMode = false;

// Pack Card Selection Logic
function togglePackCard(cardElement) {
    cardElement.classList.toggle('active');
    const checkbox = cardElement.querySelector('.pack-checkbox');
    if (checkbox) {
        checkbox.checked = cardElement.classList.contains('active');
    }
}

function toggleAllPacks() {
    const cards = document.querySelectorAll('.pack-card');
    const allActive = Array.from(cards).every(card => card.classList.contains('active'));
    cards.forEach(card => {
        if (allActive) {
            card.classList.remove('active');
            const cb = card.querySelector('.pack-checkbox');
            if (cb) cb.checked = false;
        } else {
            card.classList.add('active');
            const cb = card.querySelector('.pack-checkbox');
            if (cb) cb.checked = true;
        }
    });
}

// Mode Toggle: Board View vs Dev Patch
function setViewMode(devMode) {
    isDevPatchMode = devMode;
    const modeBoard = document.getElementById('modeBoard');
    const modeDev = document.getElementById('modeDev');
    
    if (modeBoard && modeDev) {
        if (isDevPatchMode) {
            modeDev.classList.add('bg-charcoal-800', 'text-acid');
            modeDev.classList.remove('text-alabaster/70');
            modeBoard.classList.remove('bg-charcoal-800', 'text-acid');
            modeBoard.classList.add('text-alabaster/70');
        } else {
            modeBoard.classList.add('bg-charcoal-800', 'text-acid');
            modeBoard.classList.remove('text-alabaster/70');
            modeDev.classList.remove('bg-charcoal-800', 'text-acid');
            modeDev.classList.add('text-alabaster/70');
        }
    }

    document.querySelectorAll('.code-content').forEach(el => {
        const encodedData = isDevPatchMode ? el.getAttribute('data-diff') : el.getAttribute('data-snippet');
        el.textContent = decodeURIComponent(encodedData || '');
    });
}

// Pre-computed fallback dataset (educational institution baseline)
const FALLBACK_DEMO_REPORT = {
    is_fallback: true,
    security_grade: "C",
    total_findings: 3,
    findings: [
        {
            id: "EDU-DNS-001",
            title: "Missing DMARC Policy on School Domain",
            severity: "HIGH",
            owasp_asvs_id: "ASVS v4.0 - 1.14.3",
            target_type: "domain",
            rule_logic: "dns_txt_missing_dmarc",
            description: "No restrictive DMARC TXT record detected. Threat actors can forge tuition payment invoices and admissions notices under @university.edu.",
            compliance_impact: "FERPA §99.31 Risk — Spoofed official email vectors lead to unauthorized credential phishing."
        },
        {
            id: "EDU-CFG-001",
            title: "Exposed Environment File (.env)",
            severity: "CRITICAL",
            owasp_asvs_id: "ASVS v4.0 - 14.2.1",
            target_type: "source_code",
            rule_logic: "file_exists_env",
            description: "Database credentials and JWT secret signing keys discovered in accessible environment file.",
            compliance_impact: "FERPA Direct Violation — Student educational records and SSN hashes exposed to unauthorized retrieval."
        },
        {
            id: "EDU-RBAC-001",
            title: "Missing Session Verification on Student Grade Route (IDOR)",
            severity: "CRITICAL",
            owasp_asvs_id: "ASVS v4.0 - 4.2.1",
            target_type: "source_code",
            rule_logic: "semgrep_missing_rbac",
            description: "GET /api/v1/students/{student_id}/grades route fails to assert that current authenticated session matches requested student_id.",
            compliance_impact: "FERPA Grade Privacy Violation — Unauthenticated or cross-student grade enumeration permitted."
        }
    ],
    remediations: [
        {
            executive_summary: "Configure TXT record '_dmarc.school.edu' with 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@school.edu' to block spoofed student bursar billing emails.",
            patched_code_snippet: "_dmarc.school.edu. 300 IN TXT \"v=DMARC1; p=reject; rua=mailto:security-reports@school.edu; aspf=s; adkim=s;\"",
            unified_diff: "--- a/dns/zonefile.zone\n+++ b/dns/zonefile.zone\n@@ -14,3 +14,4 @@\n+ _dmarc.school.edu. IN TXT \"v=DMARC1; p=reject; rua=mailto:security-reports@school.edu;\""
        },
        {
            executive_summary: "Immediately exclude .env from web server root, rotate exposed database secrets, and add .env to .gitignore.",
            patched_code_snippet: "# .gitignore\n.env\n.env.*\n!.env.example\ncredentials.json\n*.pem",
            unified_diff: "--- a/.gitignore\n+++ b/.gitignore\n@@ -1,2 +1,6 @@\n+ .env\n+ .env.*\n+ !.env.example\n+ credentials.json"
        },
        {
            executive_summary: "Enforce ownership middleware verifying that the requesting user's identity matches student_id before querying records.",
            patched_code_snippet: "@router.get('/students/{student_id}/grades')\nasync def get_grades(student_id: str, user=Depends(get_current_user)):\n    if user.role != 'faculty' and user.student_id != student_id:\n        raise HTTPException(status_code=403, detail='Access Denied: FERPA Protected')\n    return fetch_student_grades(student_id)",
            unified_diff: "--- a/api/students.py\n+++ b/api/students.py\n@@ -24,4 +24,7 @@\n async def get_grades(student_id: str, user=Depends(get_current_user)):\n+    if user.role != 'faculty' and user.student_id != student_id:\n+        raise HTTPException(status_code=403, detail='Access Denied: FERPA Protected')\n     return fetch_student_grades(student_id)"
        }
    ]
};

// Run Scan
async function runScan() {
    const targetInput = document.getElementById('targetInput');
    const scanModeEl = document.getElementById('scanMode');
    const modelSelector = document.getElementById('aiModelSelector');
    
    const target = targetInput ? targetInput.value.trim() : './demo_target';
    const scanMode = scanModeEl ? scanModeEl.value : 'hybrid';
    const aiModel = modelSelector ? modelSelector.value : 'gemma4:e4b';

    const selectedPacks = [];
    document.querySelectorAll('.pack-checkbox:checked').forEach(cb => {
        selectedPacks.push(cb.value);
    });

    if (selectedPacks.length === 0) {
        if (window.EduToast) {
            window.EduToast.show({
                title: "Selection Required",
                description: "Please select at least one template pack to initiate an audit.",
                stage: "error",
                duration: 4000
            });
        } else {
            alert("Please select at least one template pack.");
        }
        return;
    }

    // UI Loading state
    const emptyState = document.getElementById('emptyState');
    const resultsHeader = document.getElementById('resultsHeader');
    const findingsContainer = document.getElementById('findingsContainer');
    const loadingState = document.getElementById('loadingState');
    const loadingTitle = document.getElementById('loadingTitle');
    const loadingStepText = document.getElementById('loadingStepText');

    if (emptyState) emptyState.classList.add('hidden');
    if (resultsHeader) resultsHeader.classList.add('hidden');
    if (findingsContainer) findingsContainer.innerHTML = '';
    
    if (loadingTitle) {
        loadingTitle.textContent = `${aiModel} is Auditing...`;
    }
    if (loadingState) {
        loadingState.classList.remove('hidden');
        loadingState.classList.add('flex');
    }

    const workbench = document.getElementById('workbench');
    if (workbench) {
        workbench.scrollIntoView({ behavior: 'smooth' });
    }

    // Non-blocking Toast Progress Pipeline
    const toastId = "eduguard-audit-progress";
    if (window.EduToast) {
        window.EduToast.show({
            id: toastId,
            title: "Stage 1/3: Surface Perimeter Inspection",
            description: `Auditing ${selectedPacks.length} packs on ${target}...`,
            stage: "loading"
        });
    }

    const stage2Timer = setTimeout(() => {
        if (window.EduToast) {
            window.EduToast.show({
                id: toastId,
                title: "Stage 2/3: OWASP ASVS v4.0 Baselines",
                description: "Asserting deterministic verification rules across DNS, Transport, and RBAC...",
                stage: "stage2"
            });
        }
    }, 900);

    const stage3Timer = setTimeout(() => {
        if (window.EduToast) {
            window.EduToast.show({
                id: toastId,
                title: `Stage 3/3: ${aiModel} Remediation`,
                description: "Synthesizing verified diff patches and FERPA impact summaries locally...",
                stage: "stage3"
            });
        }
    }, 1800);

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                scan_mode: scanMode,
                selected_packs: selectedPacks,
                model_name: aiModel
            })
        });

        clearTimeout(stage2Timer);
        clearTimeout(stage3Timer);

        if (!response.ok) {
            throw new Error(`API returned ${response.status}`);
        }

        const data = await response.json();
        if (loadingState) {
            loadingState.classList.add('hidden');
            loadingState.classList.remove('flex');
        }

        if (window.EduToast) {
            window.EduToast.show({
                id: toastId,
                title: "Security Audit Complete",
                description: `Scorecard Grade ${data.security_grade || 'C'} · ${data.findings ? data.findings.length : 0} findings with ${aiModel} patches`,
                stage: "success",
                duration: 4500
            });
        }

        renderResults(data);

    } catch (error) {
        console.warn("Backend scan failed or Ollama unavailable, serving verified sample dataset:", error);
        clearTimeout(stage2Timer);
        clearTimeout(stage3Timer);
        
        // Brief simulated delay to show completion
        setTimeout(() => {
            if (loadingState) {
                loadingState.classList.add('hidden');
                loadingState.classList.remove('flex');
            }

            if (window.EduToast) {
                window.EduToast.show({
                    id: toastId,
                    title: "Audit Complete (Sample Data)",
                    description: `Local Gemma unavailable. Showing verified baseline sample report.`,
                    stage: "success",
                    duration: 4500
                });
            }

            renderResults(FALLBACK_DEMO_REPORT);
        }, 600);
    }
}

// Render Results with Consigna Bento Scorecard
function renderResults(data) {
    const resultsHeader = document.getElementById('resultsHeader');
    const gradeBadge = document.getElementById('gradeBadge');
    const totalFindingsEl = document.getElementById('totalFindings');
    const fallbackBadgeContainer = document.getElementById('fallbackBadgeContainer');
    const container = document.getElementById('findingsContainer');

    if (resultsHeader) resultsHeader.classList.remove('hidden');
    
    // Grade color formatting
    if (gradeBadge) {
        gradeBadge.textContent = data.security_grade || 'C';
        gradeBadge.className = 'font-display font-bold text-6xl leading-none';
        if (data.security_grade === 'A' || data.security_grade === 'B') {
            gradeBadge.classList.add('text-acid');
        } else if (data.security_grade === 'C') {
            gradeBadge.classList.add('text-tangerine');
        } else {
            gradeBadge.classList.add('text-crimson');
        }
    }

    if (totalFindingsEl) {
        totalFindingsEl.textContent = data.total_findings || (data.findings ? data.findings.length : 0);
    }

    // Display fallback disclaimer badge when pre-computed sample data is used
    if (fallbackBadgeContainer) {
        if (data.is_fallback) {
            fallbackBadgeContainer.innerHTML = `
                <div class="sample-data-badge">
                    <span class="w-2 h-2 rounded-full bg-tangerine inline-block animate-pulse"></span>
                    Sample data - local Gemma unavailable
                </div>
            `;
            fallbackBadgeContainer.classList.remove('hidden');
        } else {
            fallbackBadgeContainer.innerHTML = '';
            fallbackBadgeContainer.classList.add('hidden');
        }
    }

    if (!container) return;
    container.innerHTML = '';

    if (!data.findings || data.findings.length === 0) {
        container.innerHTML = `
            <div class="text-center py-24 border border-dashed border-charcoal-600 rounded-2xl bg-charcoal-700">
                <h3 class="font-display text-2xl text-acid mb-2">Target Secured</h3>
                <p class="font-mono text-sm text-alabaster/70">No vulnerabilities detected across selected template packs.</p>
            </div>
        `;
        return;
    }

    // Match findings and remediations by array index (Backend contract)
    data.findings.forEach((finding, index) => {
        const remediation = (data.remediations && data.remediations[index]) ? data.remediations[index] : null;
        const hasRemediation = !!remediation;
        const severityColor = finding.severity === 'CRITICAL' ? 'bg-crimson text-white' : (finding.severity === 'HIGH' ? 'bg-tangerine text-white' : 'bg-acid text-charcoal-900');

        const codeSnippet = (hasRemediation && remediation.patched_code_snippet) ? remediation.patched_code_snippet.replace(/</g, '&lt;').replace(/>/g, '&gt;') : 'No patch generated.';
        const unifiedDiff = (hasRemediation && remediation.unified_diff) ? remediation.unified_diff.replace(/</g, '&lt;').replace(/>/g, '&gt;') : 'No diff available.';
        const summary = (hasRemediation && remediation.executive_summary) ? remediation.executive_summary : 'Manual review required.';
        const complianceImpact = finding.compliance_impact ? `<div class="mt-3 p-2.5 rounded-lg bg-charcoal-800/90 border border-charcoal-600 text-xs font-mono text-tangerine leading-relaxed">${finding.compliance_impact}</div>` : '';

        const cardHtml = `
            <div class="finding-card bg-charcoal-700 border border-charcoal-600 rounded-2xl overflow-hidden flex flex-col lg:flex-row">
                <!-- Left Info Panel (Consigna Bento Column) -->
                <div class="p-6 lg:w-5/12 border-b lg:border-b-0 lg:border-r border-charcoal-600 flex flex-col justify-between">
                    <div>
                        <div class="flex flex-wrap items-center gap-2 mb-4">
                            <span class="px-3 py-1 text-[11px] font-bold font-mono tracking-wider rounded-full uppercase ${severityColor}">
                                ${finding.severity}
                            </span>
                            <span class="px-3 py-1 text-[11px] font-mono tracking-wider rounded-full bg-charcoal-800 text-charcoal-500 border border-charcoal-600">
                                ${finding.owasp_asvs_id}
                            </span>
                        </div>
                        <h4 class="font-display font-medium text-xl leading-tight text-white mb-2">${finding.title}</h4>
                        <p class="font-mono text-sm text-charcoal-500 leading-relaxed mb-3">${finding.description}</p>
                        ${complianceImpact}
                    </div>

                    <div class="mt-6 pt-4 border-t border-charcoal-600/60">
                        <div class="bg-charcoal-800 p-4 rounded-xl border border-charcoal-600">
                            <div class="flex items-center gap-2 mb-1.5">
                                <span class="w-1.5 h-1.5 rounded-full bg-acid"></span>
                                <h5 class="text-[11px] font-bold text-acid font-mono uppercase tracking-wider">Gemma AI Principal Summary</h5>
                            </div>
                            <p class="text-sm text-alabaster leading-relaxed font-body">${summary}</p>
                        </div>
                    </div>
                </div>

                <!-- Right Code & Diff Panel -->
                <div class="p-6 lg:w-7/12 bg-charcoal-900 flex flex-col justify-between relative">
                    <div class="flex justify-between items-center mb-3">
                        <span class="font-mono text-xs text-charcoal-600 uppercase tracking-widest">Remediation Patch</span>
                        <button onclick="copyPatch(this)" data-patch="${encodeURIComponent(hasRemediation && remediation.patched_code_snippet ? remediation.patched_code_snippet : '')}" data-diff="${encodeURIComponent(hasRemediation && remediation.unified_diff ? remediation.unified_diff : '')}" class="px-4 py-1.5 bg-charcoal-800 text-white rounded-full text-xs font-mono font-medium hover:bg-charcoal-700 transition-all border border-charcoal-600 flex items-center gap-2 copy-btn">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            Copy Patch
                        </button>
                    </div>

                    <!-- Code Preview Block -->
                    <div class="flex-1 bg-[#0A0A0A] rounded-xl border border-[#1A1A1A] p-4 overflow-x-auto min-h-[180px]">
                        <pre class="font-mono text-[13px] leading-relaxed text-gray-300 w-full"><code class="code-content" data-snippet="${encodeURIComponent(hasRemediation && remediation.patched_code_snippet ? remediation.patched_code_snippet : '')}" data-diff="${encodeURIComponent(hasRemediation && remediation.unified_diff ? remediation.unified_diff : '')}">${isDevPatchMode ? unifiedDiff : codeSnippet}</code></pre>
                    </div>
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', cardHtml);
    });
}

// Copy Patch Utility
function copyPatch(btn) {
    const rawData = isDevPatchMode ? btn.getAttribute('data-diff') : btn.getAttribute('data-patch');
    const textToCopy = decodeURIComponent(rawData || '');
    
    if (!textToCopy) return;

    navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = btn.innerHTML;
        btn.innerHTML = `<span class="text-charcoal-900 font-bold">Copied! ✓</span>`;
        btn.classList.remove('bg-charcoal-800', 'text-white');
        btn.classList.add('bg-acid');
        
        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.classList.remove('bg-acid');
            btn.classList.add('bg-charcoal-800', 'text-white');
        }, 2000);
    });
}

// Check URL query params and initialize Scan History on load
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const targetParam = params.get('target');
    const modeParam = params.get('mode');

    if (targetParam && document.getElementById('targetInput')) {
        document.getElementById('targetInput').value = targetParam;
    }
    if (modeParam && document.getElementById('scanMode')) {
        document.getElementById('scanMode').value = modeParam;
    }

    renderHistorySidebar();
});

// Scan History Manager
const DEFAULT_JINJA_HISTORY = [
    {
        id: "SCAN-9482",
        name: "Campus Core & Student Portal",
        timestamp: "Today, 16:42",
        target: "./demo_target",
        security_grade: "C",
        grade_color: "#FF6B2B",
        findings: FALLBACK_DEMO_REPORT.findings,
        remediations: FALLBACK_DEMO_REPORT.remediations,
        is_fallback: true
    },
    {
        id: "SCAN-8830",
        name: "Admissions API & Applicant Registry",
        timestamp: "Yesterday, 14:15",
        target: "https://admissions.state.edu/api/v2",
        security_grade: "B",
        grade_color: "#FF6B2B",
        findings: [
            {
                id: "EDU-TLS-002",
                title: "TLS 1.0/1.1 Deprecated Cipher Negotiation Allowed",
                severity: "HIGH",
                owasp_asvs_id: "ASVS v4.0 - 9.1.2",
                target_type: "perimeter",
                description: "Edge load balancer allows legacy TLS 1.0/1.1 connections with CBC ciphers vulnerable to POODLE attacks.",
                compliance_impact: "FERPA Transport Privacy — Weak cryptographic negotiation could allow intercepting applicant tax forms."
            }
        ],
        remediations: [
            {
                executive_summary: "Configure NGINX reverse proxy to enforce TLS 1.2 and TLS 1.3 only, disabling legacy 3DES and CBC ciphers.",
                patched_code_snippet: "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;\nssl_prefer_server_ciphers off;",
                unified_diff: "--- a/nginx/admissions.conf\n+++ b/nginx/admissions.conf\n@@ -14,2 +14,3 @@\n- ssl_protocols TLSv1.0 TLSv1.1 TLSv1.2;\n+ ssl_protocols TLSv1.2 TLSv1.3;\n+ ssl_prefer_server_ciphers off;"
            }
        ],
        is_fallback: true
    }
];

function getStoredHistory() {
    try {
        const saved = localStorage.getItem('eduguard_scan_history');
        if (saved) {
            const parsed = JSON.parse(saved);
            if (Array.isArray(parsed) && parsed.length > 0) return parsed;
        }
    } catch (e) {}
    return DEFAULT_JINJA_HISTORY;
}

function saveStoredHistory(history) {
    try {
        localStorage.setItem('eduguard_scan_history', JSON.stringify(history));
    } catch (e) {}
}

let activeHistoryReportId = "SCAN-9482";

function toggleHistorySidebar(forceOpen) {
    const sidebar = document.getElementById('historySidebar');
    const backdrop = document.getElementById('historyBackdrop');
    if (!sidebar) return;

    const isOpen = !sidebar.classList.contains('translate-x-full');
    const shouldOpen = typeof forceOpen === 'boolean' ? forceOpen : !isOpen;

    if (shouldOpen) {
        sidebar.classList.remove('translate-x-full');
        if (backdrop) backdrop.classList.remove('hidden');
        renderHistorySidebar();
    } else {
        sidebar.classList.add('translate-x-full');
        if (backdrop) backdrop.classList.add('hidden');
    }
}

function renderHistorySidebar() {
    const listContainer = document.getElementById('historyListContainer');
    const countBadge = document.getElementById('historyCountBadge');
    const filteredBadge = document.getElementById('historyFilteredBadge');
    if (!listContainer) return;

    const history = getStoredHistory();
    if (countBadge) countBadge.textContent = history.length;
    if (filteredBadge) filteredBadge.textContent = `${history.length} Reports`;

    const searchInput = document.getElementById('historySearchInput');
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';

    const filtered = history.filter(item => {
        if (!query) return true;
        return (item.target && item.target.toLowerCase().includes(query)) ||
               (item.name && item.name.toLowerCase().includes(query)) ||
               (item.id && item.id.toLowerCase().includes(query));
    });

    if (filtered.length === 0) {
        listContainer.innerHTML = `
            <div class="text-center py-12 text-alabaster/60 font-mono text-xs">
                No past scan reports match "${query}".
            </div>
        `;
        return;
    }

    listContainer.innerHTML = filtered.map(item => {
        const isActive = item.id === activeHistoryReportId;
        const gradeColor = item.security_grade === 'A' || item.security_grade === 'B' ? '#E2FF32' : '#FF6B2B';
        const findingsCount = item.findings ? item.findings.length : (item.total_findings || 0);

        return `
            <div onclick="selectHistoryReport('${item.id}')" class="p-4 rounded-xl border cursor-pointer transition-all ${isActive ? 'bg-charcoal-700 border-acid shadow-lg' : 'bg-charcoal-900 border-charcoal-600 hover:border-charcoal-500'}">
                <div class="flex items-center justify-between mb-2">
                    <span class="font-mono text-xs font-bold text-white bg-charcoal-800 px-2 py-0.5 rounded border border-charcoal-600">${item.id}</span>
                    <span class="font-mono text-[11px] text-alabaster/60">${item.timestamp || 'Recorded'}</span>
                    <span class="font-display font-bold text-base px-2 py-0.5 rounded border" style="color: ${gradeColor}; border-color: ${gradeColor}40;">Grade ${item.security_grade || 'C'}</span>
                </div>
                <h4 class="font-display font-medium text-sm text-white mb-1">${item.name || item.target}</h4>
                <p class="font-mono text-xs text-alabaster/60 truncate mb-2">Target: ${item.target}</p>
                <div class="flex items-center justify-between pt-2 border-t border-charcoal-600/60 text-xs font-mono">
                    <span class="text-alabaster/70">${findingsCount} Findings</span>
                    <span class="${isActive ? 'text-acid font-bold' : 'text-alabaster/60'}">${isActive ? '● Loaded' : 'Click to Load →'}</span>
                </div>
            </div>
        `;
    }).join('');
}

function filterHistoryList() {
    renderHistorySidebar();
}

function selectHistoryReport(reportId) {
    const history = getStoredHistory();
    const item = history.find(h => h.id === reportId);
    if (!item) return;

    activeHistoryReportId = reportId;
    renderHistorySidebar();

    if (window.EduToast) {
        window.EduToast.show({
            title: `Report Loaded: ${item.id}`,
            description: `${item.name || item.target} (Grade ${item.security_grade}) loaded into workbench.`,
            stage: "success",
            duration: 3000
        });
    }

    renderResults({
        is_fallback: true,
        security_grade: item.security_grade || 'C',
        total_findings: item.findings ? item.findings.length : 0,
        findings: item.findings || [],
        remediations: item.remediations || []
    });

    const workbench = document.getElementById('workbench');
    if (workbench) {
        workbench.scrollIntoView({ behavior: 'smooth' });
    }
}

function resetDefaultHistory() {
    localStorage.removeItem('eduguard_scan_history');
    activeHistoryReportId = DEFAULT_JINJA_HISTORY[0].id;
    renderHistorySidebar();
    if (window.EduToast) {
        window.EduToast.show({
            title: "Demo Benchmarks Restored",
            description: "Restored institutional demo scan history.",
            stage: "info",
            duration: 3000
        });
    }
}
