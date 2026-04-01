/* ============================================================
   CampusSOC Dashboard JavaScript
   ============================================================ */

'use strict';

// Chart.js global defaults for dark theme
Chart.defaults.color = '#657a96';
Chart.defaults.borderColor = '#1e2d44';
Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";
Chart.defaults.font.size = 11;

let alertTrendChart = null;
let riskChart = null;

/**
 * Initialize all dashboard charts
 */
function initCharts(alertTrendData, riskData) {
    const alertCtx = document.getElementById('alertTrendChart');
    const riskCtx = document.getElementById('riskChart');

    if (alertCtx) {
        alertTrendChart = new Chart(alertCtx, {
            type: 'line',
            data: alertTrendData,
            options: {
                responsive: true,
                maintainAspectRatio: true,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#141d2b',
                        borderColor: '#1e2d44',
                        borderWidth: 1,
                        titleColor: '#c8d6e8',
                        bodyColor: '#c8d6e8',
                        padding: 10,
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: { maxRotation: 0, maxTicksLimit: 12 }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        ticks: {
                            stepSize: 1,
                            precision: 0,
                        }
                    }
                }
            }
        });
    }

    if (riskCtx) {
        riskChart = new Chart(riskCtx, {
            type: 'doughnut',
            data: riskData,
            options: {
                responsive: true,
                cutout: '65%',
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#141d2b',
                        borderColor: '#1e2d44',
                        borderWidth: 1,
                        titleColor: '#c8d6e8',
                        bodyColor: '#c8d6e8',
                    }
                }
            }
        });
    }
}


/**
 * Refresh alert trend data via API
 */
async function refreshAlertTrend() {
    try {
        const resp = await fetch('/api/stats');
        if (!resp.ok) return;
        const data = await resp.json();

        if (alertTrendChart && data.hourly_alerts) {
            alertTrendChart.data.labels = data.hourly_alerts.map(d => d.hour);
            alertTrendChart.data.datasets[0].data = data.hourly_alerts.map(d => d.count);
            alertTrendChart.update('none');
        }

        if (riskChart && data.risk_distribution) {
            const dist = data.risk_distribution;
            riskChart.data.datasets[0].data = [dist.Safe, dist.Medium, dist.High];
            riskChart.update('none');
        }
    } catch (e) {
        console.warn('Dashboard refresh error:', e);
    }
}


/**
 * Auto-dismiss flash alerts after 5 seconds
 */
function initAutoDismissAlerts() {
    setTimeout(() => {
        document.querySelectorAll('.alert.alert-success, .alert.alert-info').forEach(el => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
            bsAlert.close();
        });
    }, 5000);
}


/**
 * Confirm dialogs for dangerous actions
 */
function initConfirmForms() {
    document.querySelectorAll('[data-confirm]').forEach(el => {
        el.addEventListener('click', (e) => {
            if (!confirm(el.dataset.confirm)) {
                e.preventDefault();
            }
        });
    });
}


/**
 * Highlight rows based on severity
 */
function initSeverityHighlight() {
    document.querySelectorAll('[data-severity]').forEach(row => {
        const sev = row.dataset.severity;
        if (sev === 'Critical') {
            row.style.borderLeft = '3px solid #dc3545';
        } else if (sev === 'High') {
            row.style.borderLeft = '3px solid #fd7e14';
        }
    });
}


/**
 * Tooltip initialization
 */
function initTooltips() {
    const tooltipEls = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipEls.forEach(el => new bootstrap.Tooltip(el, { trigger: 'hover' }));
}


// ─── Init on DOM ready ────────────────────────────────────── //

document.addEventListener('DOMContentLoaded', () => {
    initAutoDismissAlerts();
    initConfirmForms();
    initSeverityHighlight();
    initTooltips();

    // Refresh charts every 60 seconds on dashboard
    if (document.getElementById('alertTrendChart')) {
        setInterval(refreshAlertTrend, 60000);
    }
});
