document.querySelectorAll("[data-dialog-open]").forEach((button) => {
  button.addEventListener("click", () => {
    const dialog = document.getElementById(button.dataset.dialogOpen);
    if (dialog) dialog.showModal();
  });
});

if (window.location.hash) {
  const dialog = document.querySelector(window.location.hash);
  if (dialog instanceof HTMLDialogElement) dialog.showModal();
}

document.querySelectorAll("[data-sidebar-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const sidebar = document.getElementById("sidebar");
    const open = sidebar?.classList.toggle("open") || false;
    button.setAttribute("aria-expanded", String(open));
  });
});

document.querySelectorAll("[data-settings-tabs]").forEach((root) => {
  const tabs = [...root.querySelectorAll("[data-settings-tab]")];
  const panes = [...root.querySelectorAll("[data-settings-pane]")];
  const activate = (name) => {
    tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.settingsTab === name));
    panes.forEach((pane) => pane.classList.toggle("active", pane.dataset.settingsPane === name));
    const url = new URL(window.location.href);
    url.searchParams.set("section", name);
    window.history.replaceState({}, "", url);
  };
  tabs.forEach((tab) => tab.addEventListener("click", () => activate(tab.dataset.settingsTab)));
  const requested = new URL(window.location.href).searchParams.get("section");
  if (requested && tabs.some((tab) => tab.dataset.settingsTab === requested)) activate(requested);
});

document.querySelectorAll("[data-password-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = button.closest(".password-field")?.querySelector("[data-password-input]");
    if (!input) return;
    input.type = input.type === "password" ? "text" : "password";
    button.setAttribute("aria-label", input.type === "password" ? "Показать пароль" : "Скрыть пароль");
  });
});

document.querySelectorAll("[data-dialog-close]").forEach((button) => {
  button.addEventListener("click", () => button.closest("dialog")?.close());
});

document.querySelectorAll("dialog").forEach((dialog) => {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
});

document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

document.querySelectorAll("[data-subscription-period]").forEach((container) => {
  const select = container.querySelector("[data-period-type]");
  const customLabel = container.querySelector("[data-custom-days]");
  const dateLabel = container.querySelector("[data-expiry-date]");
  const customInput = customLabel?.querySelector("input");
  const dateInput = dateLabel?.querySelector("input");
  if (!select || !customLabel || !dateLabel || !customInput || !dateInput) return;

  const updatePeriodFields = () => {
    const usesCustomDays = select.value === "custom_days";
    const usesDate = select.value === "date";
    customLabel.hidden = !usesCustomDays;
    customInput.disabled = !usesCustomDays;
    customInput.required = usesCustomDays;
    dateLabel.hidden = !usesDate;
    dateInput.disabled = !usesDate;
    dateInput.required = usesDate;
  };

  select.addEventListener("change", updatePeriodFields);
  updatePeriodFields();
});

document.querySelectorAll("[data-secret-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = button.closest(".secret-row")?.querySelector("[data-secret-value]");
    if (!input) return;
    const hidden = input.classList.toggle("blurred");
    button.textContent = hidden ? "Показать" : "Скрыть";
  });
});

document.querySelectorAll("[data-secret-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const input = button.closest(".secret-row")?.querySelector("[data-secret-value]");
    if (!input) return;
    await navigator.clipboard.writeText(input.value);
    const original = button.textContent;
    button.textContent = "Скопировано";
    window.setTimeout(() => { button.textContent = original; }, 1400);
  });
});

document.querySelectorAll("[data-user-filters]").forEach((filters) => {
  const search = filters.querySelector("[data-user-search]");
  const buttons = [...filters.querySelectorAll("[data-protocol-filter]")];
  const rows = [...document.querySelectorAll("[data-user-row]")];
  const empty = document.querySelector("[data-user-filter-empty]");
  let protocol = "all";

  const applyFilters = () => {
    const query = search.value.trim().toLocaleLowerCase("ru");
    let visible = 0;
    rows.forEach((row) => {
      const matchesQuery = !query || row.dataset.search.includes(query);
      const matchesProtocol = protocol === "all" || row.dataset[protocol] === "true";
      row.hidden = !(matchesQuery && matchesProtocol);
      if (!row.hidden) visible += 1;
    });
    if (empty) empty.hidden = visible !== 0;
  };

  search.addEventListener("input", applyFilters);
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      protocol = button.dataset.protocolFilter;
      buttons.forEach((item) => item.classList.toggle("active", item === button));
      applyFilters();
    });
  });
});
