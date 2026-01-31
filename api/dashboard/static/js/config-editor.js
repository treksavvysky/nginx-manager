/**
 * NGINX config syntax highlighting using highlight.js.
 *
 * Finds all <pre data-config-viewer> elements and applies
 * NGINX syntax highlighting.
 */
document.addEventListener('DOMContentLoaded', function() {
  initConfigViewers();
});

// Re-init after HTMX swaps (for dynamically loaded content)
document.addEventListener('htmx:afterSwap', function() {
  initConfigViewers();
});

function initConfigViewers() {
  document.querySelectorAll('pre[data-config-viewer]:not(.hljs)').forEach(function(el) {
    el.classList.add('language-nginx');
    hljs.highlightElement(el);
  });
}
