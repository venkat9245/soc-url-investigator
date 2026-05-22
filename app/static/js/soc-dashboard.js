(function() {
    'use strict';
    document.addEventListener('DOMContentLoaded', function() {
        const alerts = document.querySelectorAll('.alert-dismissible');
        alerts.forEach(function(alert) {
            setTimeout(function() {
                const closeBtn = alert.querySelector('.btn-close');
                if (closeBtn) closeBtn.click();
            }, 6000);
        });
    });
    document.querySelectorAll('[data-confirm]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            if (!confirm(this.getAttribute('data-confirm') || 'Are you sure?')) e.preventDefault();
        });
    });
    document.querySelectorAll('[data-clipboard]').forEach(function(el) {
        el.addEventListener('click', function() {
            const text = this.innerText;
            if (text) {
                navigator.clipboard.writeText(text.trim()).then(function() {
                    const original = el.innerHTML;
                    el.innerHTML = '<i class="fas fa-check"></i> Copied';
                    setTimeout(function() { el.innerHTML = original; }, 2000);
                }).catch(function() { alert('Failed to copy'); });
            }
        });
    });
})();
