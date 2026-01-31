/**
 * NGINX Manager Dashboard — Core JS
 *
 * HTMX event handlers, auth redirect, toast management.
 */

// Auto-dismiss toasts after 5 seconds
document.addEventListener('htmx:afterSwap', function(event) {
  event.detail.target.querySelectorAll('.toast[data-auto-dismiss]').forEach(function(toast) {
    setTimeout(function() {
      toast.style.transition = 'opacity 0.3s';
      toast.style.opacity = '0';
      setTimeout(function() { toast.remove(); }, 300);
    }, 5000);
  });
});

// Handle 401 responses — redirect to login
document.addEventListener('htmx:responseError', function(event) {
  if (event.detail.xhr.status === 401) {
    window.location.href = '/dashboard/login';
  }
});

// Confirm before HTMX delete requests (backup for non-Alpine flows)
document.addEventListener('htmx:confirm', function(event) {
  if (event.detail.question) {
    event.preventDefault();
    if (confirm(event.detail.question)) {
      event.detail.issueRequest();
    }
  }
});

// Add loading state to buttons during HTMX requests
document.addEventListener('htmx:beforeRequest', function(event) {
  var trigger = event.detail.elt;
  if (trigger && trigger.classList && trigger.classList.contains('btn')) {
    trigger.dataset.originalText = trigger.textContent;
    trigger.disabled = true;
  }
});

document.addEventListener('htmx:afterRequest', function(event) {
  var trigger = event.detail.elt;
  if (trigger && trigger.dataset && trigger.dataset.originalText) {
    trigger.disabled = false;
    delete trigger.dataset.originalText;
  }
});
