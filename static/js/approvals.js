/**
 * Approval Automation — BITL Management UI
 *
 * Handles: pending approvals queue, automation policies CRUD,
 * webhook management, and test mode.
 */

const API_BASE = '/api/v1';

// ───────────────────────────── State ──────────────────────────────
let pendingApprovals = [];
let policies = [];
let webhooks = [];
let pollingInterval = null;

// ───────────────────────────── Init ──────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    loadAll();
    startPolling();

    document.getElementById('btn-add-policy').addEventListener('click', () => openPolicyModal());
    document.getElementById('btn-test-mode').addEventListener('click', () => openTestModal());
});

async function loadAll() {
    await Promise.all([loadPending(), loadPolicies(), loadWebhooks()]);
    updateStats();
}

function startPolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(() => loadPending().then(updateStats), 10000);
}

// ──────────────────────────── Tabs ───────────────────────────────
function setupTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        const isActive = btn.dataset.tab === tabId;
        btn.classList.toggle('border-primary-500', isActive);
        btn.classList.toggle('text-primary-600', isActive);
        btn.classList.toggle('border-transparent', !isActive);
        btn.classList.toggle('text-gray-500', !isActive);
    });
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.getElementById(`tab-${tabId}`).classList.remove('hidden');
}
// Expose for inline onclick in guide tab
window.switchTab = switchTab;

// ─────────────────────── Pending Approvals ───────────────────────
async function loadPending() {
    try {
        const r = await fetch(`${API_BASE}/approvals/pending`);
        if (!r.ok) return;
        const data = await r.json();
        pendingApprovals = data.pending || [];
        renderPending();
    } catch (e) {
        console.error('Failed to load pending:', e);
    }
}

function renderPending() {
    const container = document.getElementById('pending-list');
    const badge = document.getElementById('pending-badge');

    if (pendingApprovals.length > 0) {
        badge.textContent = pendingApprovals.length;
        badge.classList.remove('hidden');
    } else {
        badge.classList.add('hidden');
    }

    if (pendingApprovals.length === 0) {
        container.innerHTML = `
            <div class="bg-white rounded-lg shadow p-8 text-center">
                <div class="mx-auto w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-3">
                    <svg class="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                </div>
                <p class="text-gray-600 font-medium">No pending approvals</p>
                <p class="text-sm text-gray-400 mt-1">Approvals will appear here when agents request sensitive actions</p>
            </div>`;
        return;
    }

    container.innerHTML = pendingApprovals.map(a => {
        const created = new Date(a.created_at);
        const expires = new Date(a.expires_at);
        const remaining = Math.max(0, Math.round((expires - Date.now()) / 1000));
        const isTest = a.id.startsWith('test_');
        const isPii = a.vault_tokens && a.vault_tokens.length > 0;

        return `
        <div class="bg-white rounded-lg shadow hover:shadow-md transition-shadow ${isTest ? 'border-l-4 border-blue-400' : ''}">
            <div class="p-4 flex items-start justify-between gap-4">
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="font-medium text-gray-900">${escapeHtml(a.agent_name)}</span>
                        <span class="px-2 py-0.5 text-xs rounded-full ${a.request_type === 'command' ? 'bg-gray-100 text-gray-700' : 'bg-blue-100 text-blue-700'}">${escapeHtml(a.request_type)}</span>
                        ${isTest ? '<span class="px-2 py-0.5 text-xs rounded-full bg-blue-100 text-blue-700">TEST</span>' : ''}
                        ${isPii ? '<span class="px-2 py-0.5 text-xs rounded-full bg-red-100 text-red-700">PII</span>' : ''}
                    </div>
                    <p class="text-sm text-gray-600 mt-1 font-mono truncate">${escapeHtml(a.command || a.tool_name || '—')}</p>
                    <div class="flex items-center gap-3 mt-2 text-xs text-gray-400">
                        <span>Rule: ${escapeHtml(a.rule_name)}</span>
                        <span>${remaining > 0 ? remaining + 's remaining' : 'Expired'}</span>
                    </div>
                </div>
                <div class="flex gap-2 flex-shrink-0">
                    <button onclick="decideApproval('${a.id}', 'approve')"
                        class="px-3 py-1.5 bg-green-600 text-white text-sm rounded-md hover:bg-green-700 font-medium">
                        Approve
                    </button>
                    <button onclick="decideApproval('${a.id}', 'deny')"
                        class="px-3 py-1.5 bg-red-600 text-white text-sm rounded-md hover:bg-red-700 font-medium">
                        Deny
                    </button>
                </div>
            </div>
        </div>`;
    }).join('');
}

async function decideApproval(id, decision) {
    const reason = decision === 'approve' ? 'Approved via dashboard' : 'Denied via dashboard';
    try {
        const r = await fetch(`${API_BASE}/approvals/${id}/decide`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ decision, reason }),
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            SnapperUI.Toast.show(err.detail || `Failed to ${decision}`, 'error');
            return;
        }
        SnapperUI.Toast.show(`Request ${decision}d`, 'success');
        await loadPending();
        updateStats();
    } catch (e) {
        SnapperUI.Toast.show(`Error: ${e.message}`, 'error');
    }
}
window.decideApproval = decideApproval;

// ──────────────────────── Policies CRUD ──────────────────────────
async function loadPolicies() {
    try {
        const r = await fetch(`${API_BASE}/approval-policies`);
        if (!r.ok) return;
        policies = await r.json();
        renderPolicies();
    } catch (e) {
        console.error('Failed to load policies:', e);
    }
}

function renderPolicies() {
    const container = document.getElementById('policies-list');

    if (policies.length === 0) {
        container.innerHTML = `
            <div class="bg-white rounded-lg shadow p-8 text-center">
                <div class="mx-auto w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mb-3">
                    <svg class="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg>
                </div>
                <p class="text-gray-600 font-medium">No automation policies yet</p>
                <p class="text-sm text-gray-400 mt-1">Policies auto-approve or auto-deny requests matching your criteria</p>
                <button onclick="openPolicyModal()" class="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-md text-sm font-medium hover:bg-primary-700">
                    <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                    Create your first policy
                </button>
            </div>`;
        return;
    }

    container.innerHTML = policies.map(p => {
        const isActive = p.active !== false;
        const isApprove = p.decision === 'approve';
        const conditionChips = buildConditionChips(p.conditions || {});

        return `
        <div class="bg-white rounded-lg shadow hover:shadow-md transition-shadow">
            <div class="p-4 flex items-start justify-between gap-4">
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="font-medium text-gray-900">${escapeHtml(p.name)}</span>
                        <span class="px-2 py-0.5 text-xs rounded-full ${isApprove ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}">${isApprove ? 'Auto-Approve' : 'Auto-Deny'}</span>
                        <span class="px-2 py-0.5 text-xs rounded-full ${isActive ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}">${isActive ? 'Active' : 'Disabled'}</span>
                        <span class="text-xs text-gray-400">Priority: ${p.priority}</span>
                    </div>
                    <div class="flex flex-wrap gap-1.5 mt-2">${conditionChips}</div>
                    <div class="text-xs text-gray-400 mt-2">Max ${p.max_auto_per_hour}/hour</div>
                </div>
                <div class="flex gap-2 flex-shrink-0">
                    <button onclick="togglePolicy('${p.id}', ${!isActive})" title="${isActive ? 'Disable' : 'Enable'}"
                        class="p-1.5 text-gray-400 hover:text-gray-600 rounded">
                        <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${isActive ? 'M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636' : 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z'}"/></svg>
                    </button>
                    <button onclick="editPolicy('${p.id}')" title="Edit"
                        class="p-1.5 text-gray-400 hover:text-primary-600 rounded">
                        <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                    </button>
                    <button onclick="deletePolicy('${p.id}')" title="Delete"
                        class="p-1.5 text-gray-400 hover:text-red-600 rounded">
                        <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                    </button>
                </div>
            </div>
        </div>`;
    }).join('');
}

function buildConditionChips(conditions) {
    const chips = [];
    if (conditions.request_types?.length) {
        chips.push(...conditions.request_types.map(t =>
            `<span class="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded">${escapeHtml(t)}</span>`
        ));
    }
    if (conditions.command_patterns?.length) {
        chips.push(...conditions.command_patterns.map(p =>
            `<span class="px-2 py-0.5 text-xs bg-blue-50 text-blue-700 rounded font-mono">${escapeHtml(p)}</span>`
        ));
    }
    if (conditions.tool_names?.length) {
        chips.push(...conditions.tool_names.map(t =>
            `<span class="px-2 py-0.5 text-xs bg-purple-50 text-purple-700 rounded">${escapeHtml(t)}</span>`
        ));
    }
    if (conditions.min_trust_score != null) {
        chips.push(`<span class="px-2 py-0.5 text-xs bg-yellow-50 text-yellow-700 rounded">Trust &ge; ${conditions.min_trust_score}</span>`);
    }
    if (conditions.agent_names?.length) {
        chips.push(...conditions.agent_names.map(n =>
            `<span class="px-2 py-0.5 text-xs bg-green-50 text-green-700 rounded">${escapeHtml(n)}</span>`
        ));
    }
    return chips.length > 0 ? chips.join('') : '<span class="text-xs text-gray-400">Matches all requests</span>';
}

function openPolicyModal(policy) {
    const modal = document.getElementById('policy-modal');
    const title = document.getElementById('policy-modal-title');

    if (policy) {
        title.textContent = 'Edit Policy';
        document.getElementById('policy-id').value = policy.id;
        document.getElementById('policy-name').value = policy.name;
        document.getElementById('policy-decision').value = policy.decision;
        document.getElementById('policy-priority').value = policy.priority;
        document.getElementById('policy-maxhour').value = policy.max_auto_per_hour;
        document.getElementById('policy-patterns').value = (policy.conditions?.command_patterns || []).join('\n');
        document.getElementById('policy-tools').value = (policy.conditions?.tool_names || []).join(', ');
        document.getElementById('policy-trust').value = policy.conditions?.min_trust_score ?? '';
        document.getElementById('policy-agents').value = (policy.conditions?.agent_names || []).join(', ');

        // Set request type checkboxes
        document.querySelectorAll('[name="request_types"]').forEach(cb => {
            cb.checked = (policy.conditions?.request_types || []).includes(cb.value);
        });
    } else {
        title.textContent = 'Add Automation Policy';
        document.getElementById('policy-form').reset();
        document.getElementById('policy-id').value = '';
        document.getElementById('policy-priority').value = '10';
        document.getElementById('policy-maxhour').value = '100';
    }

    modal.classList.remove('hidden');
}
window.openPolicyModal = openPolicyModal;

function closePolicyModal() {
    document.getElementById('policy-modal').classList.add('hidden');
}
window.closePolicyModal = closePolicyModal;

async function savePolicy(event) {
    event.preventDefault();
    const id = document.getElementById('policy-id').value;
    const requestTypes = [...document.querySelectorAll('[name="request_types"]:checked')].map(cb => cb.value);
    const patterns = document.getElementById('policy-patterns').value.split('\n').map(s => s.trim()).filter(Boolean);
    const tools = document.getElementById('policy-tools').value.split(',').map(s => s.trim()).filter(Boolean);
    const agents = document.getElementById('policy-agents').value.split(',').map(s => s.trim()).filter(Boolean);
    const trustVal = document.getElementById('policy-trust').value;

    const body = {
        name: document.getElementById('policy-name').value,
        decision: document.getElementById('policy-decision').value,
        priority: parseInt(document.getElementById('policy-priority').value) || 10,
        max_auto_per_hour: parseInt(document.getElementById('policy-maxhour').value) || 100,
        conditions: {},
    };

    if (requestTypes.length) body.conditions.request_types = requestTypes;
    if (patterns.length) body.conditions.command_patterns = patterns;
    if (tools.length) body.conditions.tool_names = tools;
    if (agents.length) body.conditions.agent_names = agents;
    if (trustVal) body.conditions.min_trust_score = parseFloat(trustVal);

    const url = id ? `${API_BASE}/approval-policies/${id}` : `${API_BASE}/approval-policies`;
    const method = id ? 'PUT' : 'POST';

    try {
        const r = await fetch(url, {
            method,
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body),
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            SnapperUI.Toast.show(err.detail || 'Failed to save policy', 'error');
            return;
        }
        SnapperUI.Toast.show(id ? 'Policy updated' : 'Policy created', 'success');
        closePolicyModal();
        await loadPolicies();
        updateStats();
    } catch (e) {
        SnapperUI.Toast.show(`Error: ${e.message}`, 'error');
    }
}
window.savePolicy = savePolicy;

async function editPolicy(id) {
    const policy = policies.find(p => p.id === id);
    if (policy) openPolicyModal(policy);
}
window.editPolicy = editPolicy;

async function togglePolicy(id, active) {
    try {
        const r = await fetch(`${API_BASE}/approval-policies/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ active }),
        });
        if (!r.ok) {
            SnapperUI.Toast.show('Failed to toggle policy', 'error');
            return;
        }
        SnapperUI.Toast.show(active ? 'Policy enabled' : 'Policy disabled', 'success');
        await loadPolicies();
        updateStats();
    } catch (e) {
        SnapperUI.Toast.show(`Error: ${e.message}`, 'error');
    }
}
window.togglePolicy = togglePolicy;

async function deletePolicy(id) {
    if (!confirm('Delete this policy?')) return;
    try {
        const r = await fetch(`${API_BASE}/approval-policies/${id}`, { method: 'DELETE' });
        if (!r.ok) {
            SnapperUI.Toast.show('Failed to delete policy', 'error');
            return;
        }
        SnapperUI.Toast.show('Policy deleted', 'success');
        await loadPolicies();
        updateStats();
    } catch (e) {
        SnapperUI.Toast.show(`Error: ${e.message}`, 'error');
    }
}
window.deletePolicy = deletePolicy;

async function testPolicy() {
    const patterns = document.getElementById('policy-patterns').value.split('\n').map(s => s.trim()).filter(Boolean);
    const tools = document.getElementById('policy-tools').value.split(',').map(s => s.trim()).filter(Boolean);
    const trustVal = document.getElementById('policy-trust').value;
    const requestTypes = [...document.querySelectorAll('[name="request_types"]:checked')].map(cb => cb.value);

    const testCommand = prompt('Enter a test command to evaluate:', 'ls -la');
    if (!testCommand) return;

    try {
        const r = await fetch(`${API_BASE}/approval-policies/test`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                request_type: requestTypes.length ? requestTypes[0] : 'command',
                command: testCommand,
                trust_score: trustVal ? parseFloat(trustVal) : 1.0,
            }),
        });
        const data = await r.json();
        if (data.matched) {
            SnapperUI.Toast.show(`Would ${data.decision}: "${data.policy_name}" — ${data.reason}`, 'success', 8000);
        } else {
            SnapperUI.Toast.show(`No policy match — request would go to human approval`, 'warning', 8000);
        }
    } catch (e) {
        SnapperUI.Toast.show(`Test failed: ${e.message}`, 'error');
    }
}
window.testPolicy = testPolicy;

// ──────────────────────── Webhooks CRUD ──────────────────────────
async function loadWebhooks() {
    try {
        const r = await fetch(`${API_BASE}/webhooks`);
        if (!r.ok) return;
        const data = await r.json();
        webhooks = Array.isArray(data) ? data : (data.webhooks || []);
        renderWebhooks();
    } catch (e) {
        console.error('Failed to load webhooks:', e);
    }
}

function renderWebhooks() {
    const container = document.getElementById('webhooks-list');

    // Add button at top
    let addBtn = `
        <div class="flex justify-end">
            <button onclick="openWebhookModal()" class="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-md text-sm font-medium hover:bg-primary-700">
                <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                Add Webhook
            </button>
        </div>`;

    if (webhooks.length === 0) {
        container.innerHTML = `
            ${addBtn}
            <div class="bg-white rounded-lg shadow p-8 text-center">
                <div class="mx-auto w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mb-3">
                    <svg class="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                </div>
                <p class="text-gray-600 font-medium">No webhooks configured</p>
                <p class="text-sm text-gray-400 mt-1">Add a webhook so your approval bot receives events</p>
            </div>`;
        return;
    }

    container.innerHTML = addBtn + webhooks.map(wh => {
        const isActive = wh.active !== false;
        const events = wh.event_filters?.length ? wh.event_filters.join(', ') : 'All events';

        return `
        <div class="bg-white rounded-lg shadow hover:shadow-md transition-shadow">
            <div class="p-4 flex items-start justify-between gap-4">
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="font-medium text-gray-900">${escapeHtml(wh.description || 'Webhook')}</span>
                        <span class="px-2 py-0.5 text-xs rounded-full ${isActive ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}">${isActive ? 'Active' : 'Disabled'}</span>
                    </div>
                    <p class="text-sm text-gray-500 mt-1 font-mono truncate">${escapeHtml(wh.url)}</p>
                    <div class="text-xs text-gray-400 mt-1">Events: ${escapeHtml(events)}</div>
                </div>
                <div class="flex gap-2 flex-shrink-0">
                    <button onclick="testWebhook('${wh.id}')" title="Test" class="p-1.5 text-gray-400 hover:text-primary-600 rounded">
                        <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    </button>
                    <button onclick="deleteWebhook('${wh.id}')" title="Delete" class="p-1.5 text-gray-400 hover:text-red-600 rounded">
                        <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                    </button>
                </div>
            </div>
        </div>`;
    }).join('');
}

function openWebhookModal() {
    document.getElementById('webhook-form').reset();
    document.getElementById('webhook-id').value = '';
    // Pre-check approval events
    document.querySelector('[name="webhook_events"][value="request_pending_approval"]').checked = true;
    document.getElementById('webhook-modal').classList.remove('hidden');
}
window.openWebhookModal = openWebhookModal;

function closeWebhookModal() {
    document.getElementById('webhook-modal').classList.add('hidden');
}
window.closeWebhookModal = closeWebhookModal;

async function saveWebhook(event) {
    event.preventDefault();
    const eventFilters = [...document.querySelectorAll('[name="webhook_events"]:checked')].map(cb => cb.value);

    const body = {
        url: document.getElementById('webhook-url').value,
        description: document.getElementById('webhook-description').value || undefined,
        event_filters: eventFilters.length > 0 ? eventFilters : [],
        active: true,
    };

    try {
        const r = await fetch(`${API_BASE}/webhooks`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body),
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            SnapperUI.Toast.show(err.detail || 'Failed to create webhook', 'error');
            return;
        }
        SnapperUI.Toast.show('Webhook created', 'success');
        closeWebhookModal();
        await loadWebhooks();
        updateStats();
    } catch (e) {
        SnapperUI.Toast.show(`Error: ${e.message}`, 'error');
    }
}
window.saveWebhook = saveWebhook;

async function testWebhook(id) {
    try {
        const r = await fetch(`${API_BASE}/webhooks/${id}/test`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ event_type: 'request_pending_approval' }),
        });
        if (r.ok) {
            SnapperUI.Toast.show('Test webhook sent (approval event)', 'success');
        } else {
            SnapperUI.Toast.show('Test failed', 'error');
        }
    } catch (e) {
        SnapperUI.Toast.show(`Error: ${e.message}`, 'error');
    }
}
window.testWebhook = testWebhook;

async function deleteWebhook(id) {
    if (!confirm('Delete this webhook?')) return;
    try {
        const r = await fetch(`${API_BASE}/webhooks/${id}`, { method: 'DELETE' });
        if (r.ok) {
            SnapperUI.Toast.show('Webhook deleted', 'success');
            await loadWebhooks();
            updateStats();
        } else {
            SnapperUI.Toast.show('Failed to delete', 'error');
        }
    } catch (e) {
        SnapperUI.Toast.show(`Error: ${e.message}`, 'error');
    }
}
window.deleteWebhook = deleteWebhook;

// ───────────────────────── Test Mode ─────────────────────────────
async function openTestModal() {
    document.getElementById('test-result').classList.add('hidden');
    document.getElementById('test-modal').classList.remove('hidden');

    // Populate agents dropdown
    const select = document.getElementById('test-agent');
    try {
        const r = await fetch(`${API_BASE}/agents`);
        if (r.ok) {
            const data = await r.json();
            const agents = data.agents || data || [];
            select.innerHTML = '<option value="">Select an agent...</option>' +
                agents.map(a => `<option value="${a.id}">${escapeHtml(a.name)}</option>`).join('');
        }
    } catch (e) {
        // ignore
    }
}

function closeTestModal() {
    document.getElementById('test-modal').classList.add('hidden');
}
window.closeTestModal = closeTestModal;

async function runTest(event) {
    event.preventDefault();
    const resultDiv = document.getElementById('test-result');

    const body = {
        agent_id: document.getElementById('test-agent').value,
        request_type: document.getElementById('test-type').value,
        command: document.getElementById('test-command').value || 'echo test',
    };

    try {
        const r = await fetch(`${API_BASE}/approvals/test`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body),
        });
        const data = await r.json();

        if (r.ok) {
            resultDiv.innerHTML = `
                <p class="font-medium text-green-700">Test sent successfully</p>
                <p class="text-gray-600 mt-1">Approval ID: <code class="bg-gray-200 px-1 rounded text-xs">${escapeHtml(data.approval_request_id)}</code></p>
                <p class="text-gray-600">Webhooks delivered: <strong>${data.webhooks_delivered}</strong></p>
                <p class="text-xs text-gray-400 mt-2">Your bot should now receive the webhook. It can call <code class="bg-gray-200 px-1 rounded">/decide</code> on this ID to test the round-trip.</p>`;
        } else {
            resultDiv.innerHTML = `<p class="text-red-600">${escapeHtml(data.detail || 'Test failed')}</p>`;
        }
        resultDiv.classList.remove('hidden');
    } catch (e) {
        resultDiv.innerHTML = `<p class="text-red-600">Error: ${escapeHtml(e.message)}</p>`;
        resultDiv.classList.remove('hidden');
    }
}
window.runTest = runTest;

// ───────────────────────── Stats ─────────────────────────────────
function updateStats() {
    document.getElementById('stat-pending-count').textContent = pendingApprovals.length;
    document.getElementById('stat-policies').textContent = policies.filter(p => p.active !== false).length;
    document.getElementById('stat-webhooks').textContent = webhooks.filter(w => w.active !== false).length;

    // Update guide tab contextual hint
    const guideHint = document.getElementById('guide-pending-hint');
    if (guideHint) {
        if (pendingApprovals.length > 0 && policies.length === 0) {
            guideHint.classList.remove('hidden');
            const text = document.getElementById('guide-pending-text');
            if (text) text.textContent = `You have ${pendingApprovals.length} pending approval${pendingApprovals.length !== 1 ? 's' : ''} \u2014 automate repetitive decisions by creating an approval policy.`;
        } else {
            guideHint.classList.add('hidden');
        }
    }

    // Load auto-approved count from audit
    fetch(`${API_BASE}/audit/logs?page_size=1&action=APPROVAL_GRANTED`)
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            if (data?.total != null) {
                document.getElementById('stat-auto-approved').textContent = data.total;
            } else {
                document.getElementById('stat-auto-approved').textContent = '0';
            }
        })
        .catch(() => {
            document.getElementById('stat-auto-approved').textContent = '—';
        });
}

// ───────────────────────── Helpers ────────────────────────────────
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
