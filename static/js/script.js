// Smart Complaint Management System - JavaScript

// ============================================
// MODAL FUNCTIONS
// ============================================

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    }
}

function showViewModal(complaintId) {
    openModal('modal-' + complaintId);
}

function showUpdateModal(complaintId) {
    openModal('status-' + complaintId);
}

function closeModal(event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const modals = document.querySelectorAll('.modal.show');
    modals.forEach(modal => {
        modal.classList.remove('show');
    });
    document.body.style.overflow = 'auto';
}

// ============================================
// EXPORT & PRINT FUNCTIONS
// ============================================

function exportToCSV() {
    const table = document.querySelector('table');
    if (!table) {
        alert('No data to export');
        return;
    }

    let csv = [];
    const rows = table.querySelectorAll('tr');

    rows.forEach(row => {
        const cols = row.querySelectorAll('td, th');
        const csvRow = [];
        cols.forEach((col, index) => {
            if (index < cols.length - 1) {
                csvRow.push('"' + col.innerText.replace(/"/g, '""') + '"');
            }
        });
        csv.push(csvRow.join(','));
    });

    const csvContent = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv.join('\n'));
    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', 'complaints_' + new Date().getTime() + '.csv');
    link.click();
}

function printComplaints() {
    window.print();
}

// ============================================
// PASSWORD STRENGTH
// ============================================

function checkPasswordStrength() {
    const password = document.getElementById('password')?.value || '';
    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };

    updateRequirementUI('length', requirements.length);
    updateRequirementUI('uppercase', requirements.uppercase);
    updateRequirementUI('lowercase', requirements.lowercase);
    updateRequirementUI('number', requirements.number);
    updateRequirementUI('special', requirements.special);
}

function updateRequirementUI(requirement, met) {
    const element = document.getElementById(`req-${requirement}`);
    if (element) {
        if (met) {
            element.classList.add('requirement-met');
            element.classList.remove('requirement-unmet');
        } else {
            element.classList.add('requirement-unmet');
            element.classList.remove('requirement-met');
        }
    }
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
    }
}

// ============================================
// FORM VALIDATION
// ============================================

function validateComplaintForm() {
    const category = document.getElementById('category')?.value;
    const description = document.getElementById('description')?.value;

    if (!category) {
        alert('Please select a category');
        return false;
    }

    if (!description || description.trim().length < 10) {
        alert('Description must be at least 10 characters');
        return false;
    }

    return true;
}

// ============================================
// EVENT LISTENERS
// ============================================

// Initialize all event listeners on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    // View complaint button
    document.querySelectorAll('.complaint-view-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const complaintId = this.getAttribute('data-complaint-id');
            showViewModal(complaintId);
        });
    });

    // Update complaint button
    document.querySelectorAll('.complaint-update-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const complaintId = this.getAttribute('data-complaint-id');
            showUpdateModal(complaintId);
        });
    });

    // Password strength check on input
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', checkPasswordStrength);
    }
    
    console.log('Complaint system initialized');
});

// Close modal when clicking outside
window.addEventListener('click', function(event) {
    if (event.target.classList && event.target.classList.contains('modal')) {
        event.target.classList.remove('show');
        document.body.style.overflow = 'auto';
    }
});

// Close modal with Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        const modals = document.querySelectorAll('.modal.show');
        modals.forEach(modal => {
            modal.classList.remove('show');
        });
        document.body.style.overflow = 'auto';
    }
});
