// Dashboard JavaScript

let allThreats = [];
let filteredThreats = [];
let priorityChart = null;

// Load data on page load
document.addEventListener('DOMContentLoaded', function() {
    loadStatistics();
    loadThreats();
    
    // Set up filters
    document.getElementById('priorityFilter').addEventListener('change', filterThreats);
    document.getElementById('statusFilter').addEventListener('change', filterThreats);
    document.getElementById('searchInput').addEventListener('input', filterThreats);
});

// Load statistics
async function loadStatistics() {
    try {
        const response = await fetch('/api/statistics');
        const stats = await response.json();
        
        document.getElementById('totalThreats').textContent = stats.total_threats;
        document.getElementById('highCount').textContent = stats.priority_counts.HIGH || 0;
        document.getElementById('mediumCount').textContent = stats.priority_counts.MEDIUM || 0;
        document.getElementById('lowCount').textContent = stats.priority_counts.LOW || 0;
        document.getElementById('pendingCount').textContent = stats.pending_approval || 0;
        document.getElementById('approvedCount').textContent = stats.approved || 0;
        
        // Update pie chart - wait a bit to ensure Chart.js is loaded
        setTimeout(() => {
            updatePieChart(stats.priority_counts);
        }, 100);
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

// Create/update pie chart
function updatePieChart(priorityCounts) {
    const ctx = document.getElementById('priorityChart');
    
    if (!ctx) {
        console.error('Chart canvas not found!');
        return;
    }
    
    // Check if Chart is available
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded!');
        return;
    }
    
    // Destroy existing chart if it exists
    if (priorityChart) {
        priorityChart.destroy();
    }
    
    const highCount = priorityCounts.HIGH || 0;
    const mediumCount = priorityCounts.MEDIUM || 0;
    const lowCount = priorityCounts.LOW || 0;
    
    try {
        priorityChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['High Priority', 'Medium Priority', 'Low Priority'],
            datasets: [{
                label: 'Threats by Priority',
                data: [highCount, mediumCount, lowCount],
                backgroundColor: [
                    'rgba(139, 0, 0, 0.8)',    // High Priority - Dark Red (#8B0000)
                    'rgba(220, 20, 60, 0.8)',  // Medium Priority - Crimson (#DC143C)
                    'rgba(255, 107, 107, 0.8)' // Low Priority - Light Red (#FF6B6B)
                ],
                borderColor: [
                    'rgba(139, 0, 0, 1)',      // High Priority - Dark Red
                    'rgba(220, 20, 60, 1)',    // Medium Priority - Crimson
                    'rgba(255, 107, 107, 1)'   // Low Priority - Light Red
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        font: {
                            size: 14,
                            weight: '500'
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Threat Distribution by Priority',
                    font: {
                        size: 18,
                        weight: '600'
                    },
                    padding: {
                        top: 10,
                        bottom: 30
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
    } catch (error) {
        console.error('Error creating pie chart:', error);
    }
}

// Load threats
async function loadThreats() {
    try {
        const response = await fetch('/api/threats');
        allThreats = await response.json();
        filteredThreats = [...allThreats];
        displayThreats();
    } catch (error) {
        console.error('Error loading threats:', error);
        document.getElementById('threatsTableBody').innerHTML = 
            '<tr><td colspan="7" class="loading">Error loading threats. Please refresh.</td></tr>';
    }
}

// Filter threats
function filterThreats() {
    const priorityFilter = document.getElementById('priorityFilter').value;
    const statusFilter = document.getElementById('statusFilter').value;
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    
    filteredThreats = allThreats.filter(threat => {
        const matchPriority = priorityFilter === 'all' || threat.priority === priorityFilter;
        const matchStatus = statusFilter === 'all' || threat.approval_status === statusFilter;
        const matchSearch = searchTerm === '' || 
            threat.title.toLowerCase().includes(searchTerm) ||
            threat.id.toLowerCase().includes(searchTerm) ||
            threat.description.toLowerCase().includes(searchTerm);
        
        return matchPriority && matchStatus && matchSearch;
    });
    
    displayThreats();
}

// Display threats in table
function displayThreats() {
    const tbody = document.getElementById('threatsTableBody');
    
    if (filteredThreats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading">No threats match the current filters.</td></tr>';
        return;
    }
    
    tbody.innerHTML = filteredThreats.map(threat => {
        const priorityClass = `priority-${threat.priority.toLowerCase()}`;
        const statusClass = `status-${threat.approval_status.replace('_', '-')}`;
        
        return `
            <tr>
                <td><strong>${threat.id}</strong></td>
                <td>${threat.title}</td>
                <td><span class="priority-badge ${priorityClass}">${threat.priority}</span></td>
                <td>${threat.cvss || 'N/A'}</td>
                <td>${threat.buckets_hit} (${threat.total_keyword_count} keywords)</td>
                <td><span class="status-badge ${statusClass}">${formatStatus(threat.approval_status)}</span></td>
                <td><button class="view-btn" onclick="viewThreat('${threat.id}')">View Details</button></td>
            </tr>
        `;
    }).join('');
}

// Format status text
function formatStatus(status) {
    const statusMap = {
        'not_posted': 'Not Posted',
        'pending': 'Pending Approval',
        'approved': 'Approved'
    };
    return statusMap[status] || status;
}

// View threat details
async function viewThreat(threatId) {
    try {
        const response = await fetch(`/api/threat/${threatId}`);
        const threat = await response.json();
        
        if (threat.error) {
            alert('Threat not found');
            return;
        }
        
        displayThreatModal(threat);
    } catch (error) {
        console.error('Error loading threat details:', error);
        alert('Error loading threat details');
    }
}

// Display threat in modal
function displayThreatModal(threat) {
    const modalBody = document.getElementById('modalBody');
    const priorityClass = `priority-${threat.priority.toLowerCase()}`;
    const statusClass = `status-${threat.approval_status.replace('_', '-')}`;
    
    const approvalInfo = threat.approval_info ? `
        <div class="modal-section">
            <h3>Approval Information</h3>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">Status</div>
                    <div class="detail-value"><span class="status-badge ${statusClass}">${formatStatus(threat.approval_status)}</span></div>
                </div>
                ${threat.approval_info.posted_at ? `
                <div class="detail-item">
                    <div class="detail-label">Posted At</div>
                    <div class="detail-value">${new Date(threat.approval_info.posted_at).toLocaleString()}</div>
                </div>
                ` : ''}
                ${threat.approval_info.approved_at ? `
                <div class="detail-item">
                    <div class="detail-label">Approved At</div>
                    <div class="detail-value">${new Date(threat.approval_info.approved_at).toLocaleString()}</div>
                </div>
                ` : ''}
            </div>
        </div>
    ` : '';
    
    modalBody.innerHTML = `
        <div class="modal-header">
            <h2>${threat.title}</h2>
            <div class="modal-header-badges">
                <span class="priority-badge ${priorityClass}">${threat.priority} Priority</span>
                <span class="status-badge ${statusClass}">${formatStatus(threat.approval_status)}</span>
            </div>
        </div>
        
        <div class="modal-section">
            <h3>📋 Threat Report Summary</h3>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">Report ID</div>
                    <div class="detail-value"><strong>${threat.id}</strong></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Report Date</div>
                    <div class="detail-value">${threat.date || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">CVSS Score</div>
                    <div class="detail-value"><strong>${threat.cvss || 'N/A'}</strong></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Source Trust Level</div>
                    <div class="detail-value">${threat.source_trust || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Asset Category</div>
                    <div class="detail-value">${threat.asset_category ? threat.asset_category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) : 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Triage Priority</div>
                    <div class="detail-value"><span class="priority-badge ${priorityClass}">${threat.priority}</span></div>
                </div>
            </div>
        </div>
        
        <div class="modal-section">
            <h3>📝 Report Description</h3>
            <div class="report-description">
                <p>${threat.description || 'No description available.'}</p>
            </div>
        </div>
        
        <div class="modal-section">
            <h3>🔍 Triage Analysis</h3>
            <div class="triage-explanation">
                <p><strong>Analysis Result:</strong> ${threat.explanation || 'No analysis available.'}</p>
            </div>
            <div class="detail-grid" style="margin-top: 20px;">
                <div class="detail-item">
                    <div class="detail-label">Total Buckets Hit</div>
                    <div class="detail-value"><strong>${threat.buckets_hit}</strong></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Total Keywords Matched</div>
                    <div class="detail-value"><strong>${threat.total_keyword_count}</strong></div>
                </div>
            </div>
            <div class="bucket-breakdown">
                <h4 style="margin-top: 20px; margin-bottom: 10px;">Keyword Matches by Category:</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <div class="detail-label">Bucket A (Clinical)</div>
                        <div class="detail-value">${threat.bucket_counts.A || 0} matches</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Bucket B (Bio-Manufacturing)</div>
                        <div class="detail-value">${threat.bucket_counts.B || 0} matches</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Bucket C (Agriculture)</div>
                        <div class="detail-value">${threat.bucket_counts.C || 0} matches</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Bucket D (Severity)</div>
                        <div class="detail-value">${threat.bucket_counts.D || 0} matches</div>
                    </div>
                </div>
            </div>
            ${threat.auto_triggers && threat.auto_triggers.length > 0 ? `
            <div class="auto-triggers" style="margin-top: 20px;">
                <h4>⚡ Automatic Priority Triggers:</h4>
                <ul style="margin-top: 10px; padding-left: 25px; line-height: 1.8;">
                    ${threat.auto_triggers.map(trigger => `<li>${trigger}</li>`).join('')}
                </ul>
            </div>
            ` : ''}
        </div>
        
        ${approvalInfo}
    `;
    
    document.getElementById('threatModal').style.display = 'block';
}

// Close modal
function closeModal() {
    document.getElementById('threatModal').style.display = 'none';
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('threatModal');
    if (event.target === modal) {
        closeModal();
    }
}

// Refresh data
function refreshData() {
    loadStatistics();
    loadThreats();
}

