/**
 * OpenClaw Rules Manager - Dashboard JavaScript
 */

// Toast notification system
const Toast = {
    container: null,

    init() {
        this.container = document.getElementById('toast-container');
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.id = 'toast-container';
            this.container.className = 'fixed bottom-4 right-4 z-50 space-y-2';
            document.body.appendChild(this.container);
        }
    },

    show(message, type = 'info', duration = 5000) {
        const toast = document.createElement('div');
        toast.className = `toast px-4 py-3 rounded-lg shadow-lg max-w-sm ${this.getTypeClasses(type)}`;
        toast.innerHTML = `
            <div class="flex items-center">
                ${this.getIcon(type)}
                <span class="ml-2">${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-current opacity-70 hover:opacity-100">&times;</button>
            </div>
        `;

        this.container.appendChild(toast);

        if (duration > 0) {
            setTimeout(() => {
                toast.classList.add('toast-exit');
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }
    },

    getTypeClasses(type) {
        switch (type) {
            case 'success': return 'bg-green-500 text-white';
            case 'error': return 'bg-red-500 text-white';
            case 'warning': return 'bg-yellow-500 text-white';
            default: return 'bg-blue-500 text-white';
        }
    },

    getIcon(type) {
        switch (type) {
            case 'success':
                return '<svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>';
            case 'error':
                return '<svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>';
            case 'warning':
                return '<svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>';
            default:
                return '<svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>';
        }
    }
};

// API client
const API = {
    baseUrl: '/api/v1',

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        try {
            const response = await fetch(url, { ...defaultOptions, ...options });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Request failed');
            }

            return await response.json();
        } catch (error) {
            console.error(`API Error: ${endpoint}`, error);
            throw error;
        }
    },

    get(endpoint) {
        return this.request(endpoint);
    },

    post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },

    put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    },

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
};

// Utility functions
const Utils = {
    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    },

    formatRelativeTime(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diff = now - date;

        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) return `${days}d ago`;
        if (hours > 0) return `${hours}h ago`;
        if (minutes > 0) return `${minutes}m ago`;
        return 'just now';
    },

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    truncate(text, length = 100) {
        if (text.length <= length) return text;
        return text.substring(0, length) + '...';
    }
};

// Security score helper
const SecurityScore = {
    getGradeColor(grade) {
        if (grade.startsWith('A')) return { bg: 'bg-green-100', text: 'text-green-800' };
        if (grade.startsWith('B')) return { bg: 'bg-blue-100', text: 'text-blue-800' };
        if (grade.startsWith('C')) return { bg: 'bg-yellow-100', text: 'text-yellow-800' };
        if (grade.startsWith('D')) return { bg: 'bg-orange-100', text: 'text-orange-800' };
        return { bg: 'bg-red-100', text: 'text-red-800' };
    },

    getScoreColor(score) {
        if (score >= 80) return '#10b981'; // green
        if (score >= 60) return '#f59e0b'; // yellow
        return '#ef4444'; // red
    }
};

// Severity helpers
const Severity = {
    getColor(severity) {
        switch (severity.toLowerCase()) {
            case 'critical': return { bg: 'bg-red-100', text: 'text-red-800', dot: 'bg-red-500' };
            case 'high': return { bg: 'bg-orange-100', text: 'text-orange-800', dot: 'bg-orange-500' };
            case 'medium': return { bg: 'bg-yellow-100', text: 'text-yellow-800', dot: 'bg-yellow-500' };
            case 'low': return { bg: 'bg-blue-100', text: 'text-blue-800', dot: 'bg-blue-500' };
            default: return { bg: 'bg-gray-100', text: 'text-gray-800', dot: 'bg-gray-500' };
        }
    }
};

// Status helpers
const Status = {
    getAgentColor(status) {
        switch (status.toLowerCase()) {
            case 'active': return { bg: 'bg-green-100', text: 'text-green-800' };
            case 'pending': return { bg: 'bg-yellow-100', text: 'text-yellow-800' };
            case 'suspended': return { bg: 'bg-orange-100', text: 'text-orange-800' };
            case 'quarantined': return { bg: 'bg-red-100', text: 'text-red-800' };
            default: return { bg: 'bg-gray-100', text: 'text-gray-800' };
        }
    }
};

// Real-time updates via SSE (optional)
const RealTimeUpdates = {
    eventSource: null,

    connect(endpoint = '/api/v1/audit/logs/stream') {
        if (this.eventSource) {
            this.eventSource.close();
        }

        this.eventSource = new EventSource(endpoint);

        this.eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleUpdate(data);
        };

        this.eventSource.onerror = (error) => {
            console.error('SSE Error:', error);
            // Reconnect after 5 seconds
            setTimeout(() => this.connect(endpoint), 5000);
        };
    },

    disconnect() {
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
    },

    handleUpdate(data) {
        // Dispatch custom event for components to handle
        window.dispatchEvent(new CustomEvent('audit-log', { detail: data }));

        // Show toast for important events
        if (data.severity === 'critical' || data.severity === 'error') {
            Toast.show(data.message, 'error');
        }
    }
};

// Confirmation dialog
const Confirm = {
    show(message, onConfirm, onCancel) {
        const result = window.confirm(message);
        if (result && onConfirm) onConfirm();
        if (!result && onCancel) onCancel();
        return result;
    }
};

// Initialize on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
    Toast.init();
});

// Export for use in other scripts
window.OpenClawUI = {
    Toast,
    API,
    Utils,
    SecurityScore,
    Severity,
    Status,
    RealTimeUpdates,
    Confirm
};
