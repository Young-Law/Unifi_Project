/**
 * app/static/toggle.js
 * Handles toggle switch interactions for UniFi firewall rules.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Initialize Lucide icons if present
  if (window.lucide && typeof window.lucide.createIcons === "function") {
    window.lucide.createIcons();
  }

  // Bind change listener to all rule toggle switches
  const switches = document.querySelectorAll(".toggle-switch");
  switches.forEach((switchEl) => {
    switchEl.addEventListener("change", async function () {
      const ruleId = this.dataset.id;
      const loader = this.parentElement.querySelector(".loader");

      if (loader) {
        loader.classList.remove("hidden");
      }
      this.disabled = true;

      try {
        const res = await fetch(`/api/firewall/toggle_rule/${encodeURIComponent(ruleId)}`, {
          method: "POST",
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          alert(errData.detail || "Failed to update firewall rule.");
          this.checked = !this.checked; // Revert checkbox on error
        } else {
          // Reload page to reflect updated rule status and statistics
          window.location.reload();
        }
      } catch (err) {
        alert("Network error: Could not reach the server.");
        this.checked = !this.checked; // Revert checkbox on error
      } finally {
        if (loader) {
          loader.classList.add("hidden");
        }
        this.disabled = false;
      }
    });
  });
});
