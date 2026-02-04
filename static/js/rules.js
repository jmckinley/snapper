/**
 * OpenClaw Rules Manager - Rules Management JavaScript
 */

let currentPage = 1;
let currentFilters = {};

// Load rules with filters
async function loadRules(page = 1) {
    currentPage = page;

    const type = document.getElementById('filter-type')?.value || '';
    const agent = document.getElementById('filter-agent')?.value || '';
    const status = document.getElementById('filter-status')?.value || '';

    let url = `/api/v1/rules?page=${page}&page_size=20`;
    if (type) url += `&rule_type=${type}`;
    if (agent) url += `&agent_id=${agent}`;
    if (status !== '') url += `&is_active=${status}`;

    try {
        const response = await fetch(url);
        const data = await response.json();
        renderRulesTable(data.items);
        renderPagination(data.page, data.pages, data.total);
    } catch (error) {
        console.error('Failed to load rules:', error);
        document.getElementById('rules-table-body').innerHTML =
            '<tr><td colspan="7" class="px-6 py-4 text-center text-red-500">Failed to load rules</td></tr>';
    }
}

// Load agents for filter dropdown
async function loadAgents() {
    try {
        const response = await fetch('/api/v1/agents?page_size=100');
        const data = await response.json();

        const select = document.getElementById('filter-agent');
        if (select) {
            data.items.forEach(agent => {
                const option = document.createElement('option');
                option.value = agent.id;
                option.textContent = agent.name;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Failed to load agents:', error);
    }
}

// Render rules table
function renderRulesTable(rules) {
    const tbody = document.getElementById('rules-table-body');

    if (rules.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="px-6 py-12 text-center">
                    <div class="empty-state">
                        <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                        </svg>
                        <p class="mt-2 text-gray-500">No rules found</p>
                        <a href="/rules/create" class="mt-2 inline-block text-primary-600 hover:text-primary-500">Create your first rule</a>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = rules.map(rule => `
        <tr class="hover:bg-gray-50">
            <td class="px-6 py-4">
                <div>
                    <div class="text-sm font-medium text-gray-900">${escapeHtml(rule.name)}</div>
                    <div class="text-sm text-gray-500">${escapeHtml(rule.description || '')}</div>
                </div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 py-1 text-xs font-medium rounded-full bg-gray-100 text-gray-800">
                    ${formatRuleType(rule.rule_type)}
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 py-1 text-xs font-medium rounded-full ${getActionColor(rule.action)}">
                    ${rule.action}
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                ${rule.priority}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                ${rule.agent_id ? `<span class="text-gray-900">Specific</span>` : '<span class="text-blue-600">Global</span>'}
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 py-1 text-xs font-medium rounded-full ${rule.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}">
                    ${rule.is_active ? 'Active' : 'Inactive'}
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                <button onclick="editRule('${rule.id}')" class="text-primary-600 hover:text-primary-900 mr-3">Edit</button>
                <button onclick="toggleRule('${rule.id}', ${!rule.is_active})" class="text-gray-600 hover:text-gray-900 mr-3">
                    ${rule.is_active ? 'Disable' : 'Enable'}
                </button>
                <button onclick="deleteRule('${rule.id}')" class="text-red-600 hover:text-red-900">Delete</button>
            </td>
        </tr>
    `).join('');
}

// Render pagination
function renderPagination(current, total, totalItems) {
    const container = document.getElementById('pagination');
    if (!container) return;

    if (total <= 1) {
        container.innerHTML = `<span class="text-sm text-gray-500">${totalItems} rule${totalItems !== 1 ? 's' : ''}</span>`;
        return;
    }

    let html = `
        <div class="flex-1 flex justify-between sm:hidden">
            <button onclick="loadRules(${current - 1})" ${current === 1 ? 'disabled' : ''} class="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed">
                Previous
            </button>
            <button onclick="loadRules(${current + 1})" ${current === total ? 'disabled' : ''} class="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed">
                Next
            </button>
        </div>
        <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
            <div>
                <p class="text-sm text-gray-700">
                    Showing page <span class="font-medium">${current}</span> of <span class="font-medium">${total}</span>
                    (<span class="font-medium">${totalItems}</span> total rules)
                </p>
            </div>
            <div>
                <nav class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
    `;

    // Previous button
    html += `
        <button onclick="loadRules(${current - 1})" ${current === 1 ? 'disabled' : ''} class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed">
            <span class="sr-only">Previous</span>
            <svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M12.707 5.293a1 1 0 010 1.414L9.414 10l3.293 3.293a1 1 0 01-1.414 1.414l-4-4a1 1 0 010-1.414l4-4a1 1 0 011.414 0z" clip-rule="evenodd" /></svg>
        </button>
    `;

    // Page numbers
    for (let i = 1; i <= total; i++) {
        if (i === current) {
            html += `<button class="relative inline-flex items-center px-4 py-2 border border-primary-500 bg-primary-50 text-sm font-medium text-primary-600">${i}</button>`;
        } else if (i === 1 || i === total || (i >= current - 1 && i <= current + 1)) {
            html += `<button onclick="loadRules(${i})" class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700 hover:bg-gray-50">${i}</button>`;
        } else if (i === current - 2 || i === current + 2) {
            html += `<span class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700">...</span>`;
        }
    }

    // Next button
    html += `
        <button onclick="loadRules(${current + 1})" ${current === total ? 'disabled' : ''} class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed">
            <span class="sr-only">Next</span>
            <svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" /></svg>
        </button>
    `;

    html += `</nav></div></div>`;
    container.innerHTML = html;
}

// Apply filters
function applyFilters() {
    loadRules(1);
}

// Format rule type for display
function formatRuleType(type) {
    return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

// Get action color classes
function getActionColor(action) {
    switch (action) {
        case 'deny': return 'bg-red-100 text-red-800';
        case 'allow': return 'bg-green-100 text-green-800';
        case 'require_approval': return 'bg-yellow-100 text-yellow-800';
        case 'log_only': return 'bg-blue-100 text-blue-800';
        default: return 'bg-gray-100 text-gray-800';
    }
}

// Edit rule
function editRule(id) {
    window.location.href = `/rules/edit/${id}`;
}

// Toggle rule active status
async function toggleRule(id, active) {
    try {
        const response = await fetch(`/api/v1/rules/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_active: active })
        });

        if (response.ok) {
            loadRules(currentPage);
            if (window.OpenClawUI) {
                window.OpenClawUI.Toast.show(`Rule ${active ? 'enabled' : 'disabled'}`, 'success');
            }
        } else {
            throw new Error('Failed to update rule');
        }
    } catch (error) {
        console.error('Failed to toggle rule:', error);
        if (window.OpenClawUI) {
            window.OpenClawUI.Toast.show('Failed to update rule', 'error');
        }
    }
}

// Delete rule
async function deleteRule(id) {
    if (!confirm('Are you sure you want to delete this rule?')) return;

    try {
        const response = await fetch(`/api/v1/rules/${id}`, { method: 'DELETE' });

        if (response.ok) {
            loadRules(currentPage);
            if (window.OpenClawUI) {
                window.OpenClawUI.Toast.show('Rule deleted', 'success');
            }
        } else {
            throw new Error('Failed to delete rule');
        }
    } catch (error) {
        console.error('Failed to delete rule:', error);
        if (window.OpenClawUI) {
            window.OpenClawUI.Toast.show('Failed to delete rule', 'error');
        }
    }
}

// Apply template
async function applyTemplate(templateId) {
    try {
        const response = await fetch(`/api/v1/rules/templates/${templateId}/apply`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        if (response.ok) {
            loadRules(currentPage);
            if (window.OpenClawUI) {
                window.OpenClawUI.Toast.show('Template applied successfully', 'success');
            }
        } else {
            throw new Error('Failed to apply template');
        }
    } catch (error) {
        console.error('Failed to apply template:', error);
        if (window.OpenClawUI) {
            window.OpenClawUI.Toast.show('Failed to apply template', 'error');
        }
    }
}

// HTML escape utility
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
