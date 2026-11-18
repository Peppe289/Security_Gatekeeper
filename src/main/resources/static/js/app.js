// Progressive enhancement only: the dashboard works without JavaScript.
// No inline scripts (strict CSP), no background polling.
(function () {
    "use strict";

    // Confirmation for destructive actions: <button data-confirm="...">
    document.addEventListener("click", function (event) {
        var button = event.target.closest("[data-confirm]");
        if (button && !window.confirm(button.getAttribute("data-confirm"))) {
            event.preventDefault();
        }
    });

    // Copy buttons: <button data-copy="#selector">
    document.addEventListener("click", function (event) {
        var button = event.target.closest("[data-copy]");
        if (!button) {
            return;
        }
        var source = document.querySelector(button.getAttribute("data-copy"));
        if (source && navigator.clipboard) {
            navigator.clipboard.writeText(source.textContent.trim()).then(function () {
                button.textContent = "Copied";
            });
        }
    });

    // Render ISO-8601 instants in the browser's local time.
    document.addEventListener("DOMContentLoaded", function () {
        document.querySelectorAll("time[data-local]").forEach(function (el) {
            var date = new Date(el.getAttribute("datetime"));
            if (!isNaN(date)) {
                el.textContent = date.toLocaleString();
            }
        });
    });
})();
