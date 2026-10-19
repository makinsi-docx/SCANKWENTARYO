"use strict";

const STORAGE_KEY = "stockroom-inventory-v1";
const SALES_STORAGE_KEY = "stockroom-sales-v1";
const AUTH_STORAGE_KEY = "stockroom-local-account-v1";
const AUTH_SESSION_KEY = "stockroom-local-session-v1";
const PASSWORD_HASH_ITERATIONS = 310000;
const starterProducts = [
  { id: "seed-1", name: "Everyday Ceramic Mug", sku: "HOM-1042", category: "Home & living", price: 18.5, quantity: 4, reorderLevel: 12, location: "Shelf A3" },
  { id: "seed-2", name: "Linen Market Tote", sku: "ACC-2081", category: "Accessories", price: 24, quantity: 8, reorderLevel: 10, location: "Shelf B1" },
  { id: "seed-3", name: "Botanical Hand Soap", sku: "BTY-0316", category: "Beauty", price: 12, quantity: 3, reorderLevel: 8, location: "Shelf C2" },
  { id: "seed-4", name: "Oak Desk Organizer", sku: "HOM-1175", category: "Home & living", price: 36, quantity: 15, reorderLevel: 5, location: "Shelf A1" },
  { id: "seed-5", name: "Soft Knit Beanie", sku: "APP-4408", category: "Apparel", price: 28, quantity: 22, reorderLevel: 6, location: "Rack D2" },
  { id: "seed-6", name: "Citrus Tea Tin", sku: "KIT-5503", category: "Food & drink", price: 16, quantity: 0, reorderLevel: 10, location: "Shelf E4" },
  { id: "seed-7", name: "Pocket Notebook Set", sku: "STA-6132", category: "Stationery", price: 14.5, quantity: 31, reorderLevel: 8, location: "Shelf F2" }
];

const elements = {
  authScreen: document.querySelector("#auth-screen"),
  authForm: document.querySelector("#auth-form"),
  authTitle: document.querySelector("#auth-title"),
  authSubtitle: document.querySelector("#auth-subtitle"),
  authNameField: document.querySelector("#auth-name-field"),
  authName: document.querySelector("#auth-name"),
  authEmail: document.querySelector("#auth-email"),
  authPassword: document.querySelector("#auth-password"),
  authPasswordToggle: document.querySelector("#auth-password-toggle"),
  authError: document.querySelector("#auth-error"),
  authSubmit: document.querySelector("#auth-submit"),
  authSwitchPrompt: document.querySelector("#auth-switch-prompt"),
  authSwitchButton: document.querySelector("#auth-switch-button"),
  appShell: document.querySelector("#app-shell"),
  profileName: document.querySelector("#profile-name"),
  profileEmail: document.querySelector("#profile-email"),
  logoutButton: document.querySelector("#logout-button"),
  overview: document.querySelector("#overview-view"),
  products: document.querySelector("#products-view"),
  pointOfSale: document.querySelector("#pos-view"),
  totalProducts: document.querySelector("#total-products"),
  totalUnits: document.querySelector("#total-units"),
  inventoryValue: document.querySelector("#inventory-value"),
  lowStockCount: document.querySelector("#low-stock-count"),
  attentionBadge: document.querySelector("#attention-badge"),
  lowStockList: document.querySelector("#low-stock-list"),
  recentProducts: document.querySelector("#recent-products"),
  catalogProducts: document.querySelector("#catalog-products"),
  navProductCount: document.querySelector("#nav-product-count"),
  catalogCount: document.querySelector("#catalog-count"),
  catalogSummary: document.querySelector("#catalog-summary"),
  categoryFilter: document.querySelector("#category-filter"),
  search: document.querySelector("#product-search"),
  posSearch: document.querySelector("#pos-search"),
  posProductGrid: document.querySelector("#pos-product-grid"),
  posProductCount: document.querySelector("#pos-product-count"),
  posEmpty: document.querySelector("#pos-empty"),
  posCartItems: document.querySelector("#pos-cart-items"),
  posCartCount: document.querySelector("#pos-cart-count"),
  posSubtotal: document.querySelector("#pos-subtotal"),
  posTotal: document.querySelector("#pos-total"),
  posCash: document.querySelector("#pos-cash"),
  posChange: document.querySelector("#pos-change"),
  posCheckout: document.querySelector("#pos-checkout"),
  posPaymentError: document.querySelector("#pos-payment-error"),
  posSalesHistory: document.querySelector("#pos-sales-history"),
  emptyState: document.querySelector("#empty-state"),
  emptyTitle: document.querySelector("#empty-title"),
  emptyMessage: document.querySelector("#empty-message"),
  productDialog: document.querySelector("#product-dialog"),
  productForm: document.querySelector("#product-form"),
  productError: document.querySelector("#product-error"),
  stockDialog: document.querySelector("#stock-dialog"),
  stockForm: document.querySelector("#stock-form"),
  stockError: document.querySelector("#stock-error"),
  toast: document.querySelector("#toast")
};

let products = loadProducts();
let sales = loadSales();
let cart = new Map();
let activeView = "pos";
let toastTimer;
let accounts = [];
let setupMode = false;

function isValidAccount(account) {
  return account && typeof account.name === "string" && !!account.name.trim() &&
    typeof account.email === "string" && !!account.email.trim() &&
    typeof account.salt === "string" && /^[0-9a-f]{32}$/i.test(account.salt) &&
    typeof account.passwordHash === "string" && /^[0-9a-f]{64}$/i.test(account.passwordHash);
}

function readAccounts() {
  const saved = localStorage.getItem(AUTH_STORAGE_KEY);
  if (saved === null) return [];
  const parsed = JSON.parse(saved);
  const savedAccounts = Array.isArray(parsed) ? parsed : [parsed];
  if (!savedAccounts.every(isValidAccount) ||
      new Set(savedAccounts.map((account) => account.email.toLowerCase())).size !== savedAccounts.length) {
    throw new Error("The saved local account is invalid.");
  }
  return savedAccounts;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, salt) {
  if (!window.crypto?.subtle) {
    throw new Error("Secure password hashing is unavailable. Open this app in a modern browser using localhost or HTTPS.");
  }
  const key = await window.crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await window.crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: PASSWORD_HASH_ITERATIONS,
    hash: "SHA-256"
  }, key, 256);
  return bytesToHex(new Uint8Array(bits));
}

function setPasswordVisibility(isVisible) {
  elements.authPassword.type = isVisible ? "text" : "password";
  elements.authPasswordToggle.setAttribute("aria-label", `${isVisible ? "Hide" : "Show"} password`);
  elements.authPasswordToggle.setAttribute("aria-pressed", String(isVisible));
  elements.authPasswordToggle.querySelector(".password-eye-shape").setAttribute("d", isVisible
    ? "M3 3 21 21M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 5.2A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a15.8 15.8 0 0 1-3.1 3.9M6.2 6.2C3.5 8 2 12 2 12s3.6 7 10 7a10.8 10.8 0 0 0 4-.8"
    : "M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Zm7-3a3 3 0 1 0 6 6 3 3 0 0 0-6-6Z");
}

function setAuthMode(isSetup) {
  setupMode = isSetup;
  setPasswordVisibility(false);
  elements.authTitle.innerHTML = isSetup ? "Set up your account<span>.</span>" : "Welcome back<span>.</span>";
  elements.authSubtitle.textContent = isSetup
    ? "Create an account to access this browser’s shared inventory."
    : "Sign in to manage your inventory.";
  elements.authNameField.classList.toggle("hidden", !isSetup);
  elements.authName.required = isSetup;
  elements.authPassword.autocomplete = isSetup ? "new-password" : "current-password";
  elements.authSubmit.innerHTML = isSetup ? "Create account <span aria-hidden=\"true\">→</span>" : "Sign in <span aria-hidden=\"true\">→</span>";
  elements.authSwitchPrompt.textContent = isSetup ? "Already have an account?" : "New to Scankwentory?";
  elements.authSwitchButton.textContent = isSetup ? "Sign in" : "Create an account";
}

function showInventory(user) {
  elements.authScreen.classList.add("hidden");
  elements.appShell.classList.remove("hidden");
  elements.profileName.textContent = user.name;
  elements.profileEmail.textContent = user.email;
  document.querySelector(".avatar").textContent = initials(user.name);
  setView("pos");
  render();
}

function initializeAuth() {
  try {
    accounts = readAccounts();
    setAuthMode(accounts.length === 0);
    const activeSession = sessionStorage.getItem(AUTH_SESSION_KEY);
    const activeAccount = accounts.find((user) => user.email.toLowerCase() === activeSession);
    if (activeAccount) {
      showInventory(activeAccount);
    } else {
      sessionStorage.removeItem(AUTH_SESSION_KEY);
      elements.authScreen.classList.remove("hidden");
    }
  } catch (error) {
    console.error("Unable to read the local account.", error);
    setAuthMode(false);
    elements.authScreen.classList.remove("hidden");
    elements.authError.textContent = "Could not read the saved account. Account data may be damaged or browser storage may be unavailable.";
    elements.authError.classList.remove("hidden");
    elements.authSubmit.disabled = true;
  }
}

function loadProducts() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === null) return starterProducts.map((product) => ({ ...product }));
    const parsed = JSON.parse(saved);
    if (!Array.isArray(parsed) || !parsed.every(isValidProduct)) {
      throw new Error("Saved inventory has an invalid format.");
    }
    return parsed;
  } catch (error) {
    console.error("Unable to load inventory from local storage.", error);
    return starterProducts.map((product) => ({ ...product }));
  }
}

function isValidSale(sale) {
  return sale && typeof sale.id === "string" && typeof sale.date === "string" &&
    Number.isFinite(Date.parse(sale.date)) && Number.isFinite(sale.total) && sale.total >= 0 &&
    Number.isFinite(sale.cashReceived) && sale.cashReceived >= sale.total &&
    Number.isFinite(sale.change) && sale.change >= 0 && Array.isArray(sale.items) &&
    sale.items.length > 0 && sale.items.every((item) =>
      item && typeof item.name === "string" && typeof item.sku === "string" &&
      Number.isFinite(item.price) && item.price >= 0 &&
      Number.isInteger(item.quantity) && item.quantity > 0
    );
}

function loadSales() {
  try {
    const saved = localStorage.getItem(SALES_STORAGE_KEY);
    if (saved === null) return [];
    const parsed = JSON.parse(saved);
    if (!Array.isArray(parsed) || !parsed.every(isValidSale)) {
      throw new Error("Saved sales history has an invalid format.");
    }
    return parsed;
  } catch (error) {
    console.error("Unable to load sales history from local storage.", error);
    return [];
  }
}

function isValidProduct(product) {
  return product && typeof product.id === "string" &&
    typeof product.name === "string" && typeof product.sku === "string" &&
    typeof product.category === "string" && typeof product.location === "string" &&
    Number.isFinite(product.price) && product.price >= 0 &&
    Number.isInteger(product.quantity) && product.quantity >= 0 &&
    Number.isInteger(product.reorderLevel) && product.reorderLevel >= 0;
}

function saveProducts() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(products));
    document.querySelector(".status-indicator").innerHTML = "<i></i> All changes saved";
  } catch (error) {
    console.error("Unable to save inventory to local storage.", error);
    document.querySelector(".status-indicator").innerHTML = "<i class=\"save-error\"></i> Save failed";
    showToast("Could not save changes. Check your browser storage settings.");
    return false;
  }
  return true;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function initials(name) {
  return name.trim().split(/\s+/).slice(0, 2).map((word) => word[0]).join("");
}

function formatMoney(value) {
  return new Intl.NumberFormat("en-PH", { style: "currency", currency: "PHP" }).format(value);
}

function getStatus(product) {
  if (product.quantity === 0) return { label: "Out of stock", className: "out" };
  if (product.quantity <= product.reorderLevel) return { label: "Low stock", className: "low" };
  return { label: "In stock", className: "in-stock" };
}

function statusMarkup(product) {
  const status = getStatus(product);
  return `<span class="status-pill ${status.className}">${status.label}</span>`;
}

function productCell(product) {
  return `<div class="table-product"><span class="product-thumb">${escapeHtml(initials(product.name))}</span><strong>${escapeHtml(product.name)}</strong></div>`;
}

function renderDashboard() {
  const lowStock = products.filter((product) => product.quantity <= product.reorderLevel);
  const units = products.reduce((total, product) => total + product.quantity, 0);
  const value = products.reduce((total, product) => total + product.price * product.quantity, 0);

  elements.totalProducts.textContent = products.length.toLocaleString();
  elements.totalUnits.textContent = units.toLocaleString();
  elements.inventoryValue.textContent = formatMoney(value);
  elements.lowStockCount.textContent = lowStock.length.toLocaleString();
  elements.attentionBadge.textContent = lowStock.length.toLocaleString();
  elements.navProductCount.textContent = products.length.toLocaleString();

  if (lowStock.length === 0) {
    elements.lowStockList.innerHTML = `<div class="empty-inline"><span class="all-clear-mark">✓</span><span><strong>All stocked up</strong><small>Every product is above its reorder level.</small></span></div>`;
  } else {
    elements.lowStockList.innerHTML = lowStock.slice(0, 4).map((product) => {
      const meter = product.reorderLevel === 0 ? (product.quantity === 0 ? 0 : 100) : Math.min(100, product.quantity / product.reorderLevel * 100);
      return `<div class="attention-row">
        <div class="product-cell"><span class="product-thumb">${escapeHtml(initials(product.name))}</span><span class="product-copy"><strong>${escapeHtml(product.name)}</strong><span>${escapeHtml(product.sku)}</span></span></div>
        <div class="stock-meter"><span>${product.quantity} left</span><span class="meter-track"><i class="meter-fill" style="width:${meter}%"></i></span></div>
        <div class="reorder-cell">Reorder at ${product.reorderLevel}</div>
        ${statusMarkup(product)}
        <button class="inline-stock-button" type="button" data-adjust-stock="${escapeHtml(product.id)}" data-stock-direction="add">＋ Restock</button>
      </div>`;
    }).join("");
  }

  const recent = [...products].slice(-5).reverse();
  elements.recentProducts.innerHTML = recent.length ? recent.map((product) => `<tr>
    <td>${productCell(product)}</td><td class="sku-cell">${escapeHtml(product.sku)}</td>
    <td><span class="category-tag">${escapeHtml(product.category)}</span></td>
    <td class="money-cell">${formatMoney(product.price)}</td><td class="quantity-cell">${product.quantity}</td><td>${statusMarkup(product)}</td>
  </tr>`).join("") : `<tr><td class="table-empty" colspan="6">Your catalog is empty. Add a product to get started.</td></tr>`;
}

function renderCatalog() {
  const searchTerm = elements.search.value.trim().toLowerCase();
  const selectedCategory = elements.categoryFilter.value;
  const categories = [...new Set(products.map((product) => product.category))].sort((a, b) => a.localeCompare(b));
  const previousCategory = elements.categoryFilter.value;
  elements.categoryFilter.innerHTML = `<option value="">All products</option><option value="__low_stock__">Low stock</option><option value="__out_of_stock__">Out of stock</option><optgroup label="Categories">${categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`).join("")}</optgroup>`;
  elements.categoryFilter.value = categories.includes(previousCategory) || ["__low_stock__", "__out_of_stock__"].includes(previousCategory) ? previousCategory : "";

  const filtered = products.filter((product) => {
    const searchable = `${product.name} ${product.sku} ${product.category} ${product.location}`.toLowerCase();
    const statusMatches = elements.categoryFilter.value === "__low_stock__"
      ? product.quantity <= product.reorderLevel
      : elements.categoryFilter.value === "__out_of_stock__"
        ? product.quantity === 0
        : !elements.categoryFilter.value || product.category === elements.categoryFilter.value;
    return (!searchTerm || searchable.includes(searchTerm)) &&
      statusMatches;
  });
  elements.catalogCount.textContent = filtered.length.toLocaleString();
  elements.catalogSummary.textContent = `Showing ${filtered.length} of ${products.length} product${products.length === 1 ? "" : "s"}`;
  elements.catalogProducts.innerHTML = filtered.map((product) => `<tr>
    <td>${productCell(product)}</td><td class="sku-cell">${escapeHtml(product.sku)}</td>
    <td><span class="category-tag">${escapeHtml(product.category)}</span></td>
    <td class="money-cell">${formatMoney(product.price)}</td><td class="quantity-cell">${product.quantity}</td>
    <td>${statusMarkup(product)}</td>
    <td><div class="row-actions">
      <button class="stock-action stock-add" type="button" data-adjust-stock="${escapeHtml(product.id)}" data-stock-direction="add" aria-label="Add stock for ${escapeHtml(product.name)}" title="Add stock">＋ Add</button>
      <button class="stock-action stock-remove" type="button" data-adjust-stock="${escapeHtml(product.id)}" data-stock-direction="remove" aria-label="Record sold items for ${escapeHtml(product.name)}" title="Record sold items">− Sold</button>
      <button class="row-action" type="button" data-edit-product="${escapeHtml(product.id)}" aria-label="Edit ${escapeHtml(product.name)}" title="Edit product"><svg viewBox="0 0 24 24"><path d="m15 5 4 4M4 20l4-.8L19 8a2.1 2.1 0 0 0-3-3L5 16l-1 4Z"/></svg></button>
      <button class="row-action delete-action" type="button" data-delete-product="${escapeHtml(product.id)}" aria-label="Delete ${escapeHtml(product.name)}" title="Delete product"><svg viewBox="0 0 24 24"><path d="M4 7h16m-10 4v6m4-6v6M5 7l1 14h12l1-14M9 7V4h6v3"/></svg></button>
    </div></td>
  </tr>`).join("");

  const hasProducts = filtered.length > 0;
  elements.emptyState.classList.toggle("hidden", hasProducts);
  elements.catalogProducts.closest("table").classList.toggle("hidden", !hasProducts);
  if (!products.length) {
    elements.emptyTitle.textContent = "Your catalog is ready";
    elements.emptyMessage.textContent = "Add your first product to start tracking your inventory.";
  } else {
    elements.emptyTitle.textContent = "No products found";
    elements.emptyMessage.textContent = "Try another search or category, or clear your filters.";
  }
}

function cartTotal() {
  return Math.round(products.reduce((total, product) =>
    total + product.price * (cart.get(product.id) || 0), 0) * 100) / 100;
}

function renderPos() {
  const searchTerm = elements.posSearch.value.trim().toLowerCase();
  const availableProducts = products.filter((product) => product.quantity > 0);
  const visibleProducts = availableProducts.filter((product) =>
    `${product.name} ${product.sku} ${product.category}`.toLowerCase().includes(searchTerm)
  );
  elements.posProductCount.textContent = `${availableProducts.length} in-stock product${availableProducts.length === 1 ? "" : "s"}`;
  elements.posProductGrid.innerHTML = visibleProducts.map((product) => {
    const inCart = cart.get(product.id) || 0;
    const unavailable = inCart >= product.quantity;
    return `<button class="pos-product-card" type="button" data-pos-add="${escapeHtml(product.id)}" ${unavailable ? "disabled" : ""}>
      <span class="pos-product-initials">${escapeHtml(initials(product.name))}</span>
      <span class="pos-product-copy"><strong>${escapeHtml(product.name)}</strong><small>${escapeHtml(product.sku)} · ${product.quantity - inCart} in stock</small></span>
      <span class="pos-product-price">${formatMoney(product.price)}</span>
    </button>`;
  }).join("");
  elements.posEmpty.classList.toggle("hidden", visibleProducts.length > 0);

  const cartEntries = [...cart.entries()].map(([id, quantity]) => ({
    product: products.find((product) => product.id === id),
    quantity
  })).filter((entry) => entry.product);
  const unitCount = cartEntries.reduce((total, entry) => total + entry.quantity, 0);
  const total = cartTotal();
  const cashReceived = Number(elements.posCash.value);
  const validPayment = elements.posCash.value.trim() !== "" &&
    Number.isFinite(cashReceived) && cashReceived >= total;
  elements.posCartCount.textContent = unitCount.toLocaleString();
  elements.posCartItems.innerHTML = cartEntries.length ? cartEntries.map(({ product, quantity }) => `<div class="pos-cart-item">
    <div class="pos-cart-copy"><strong>${escapeHtml(product.name)}</strong><small>${formatMoney(product.price)} each</small></div>
    <div class="pos-cart-controls">
      <button type="button" data-pos-decrease="${escapeHtml(product.id)}" aria-label="Remove one ${escapeHtml(product.name)}">−</button>
      <span>${quantity}</span>
      <button type="button" data-pos-increase="${escapeHtml(product.id)}" aria-label="Add one ${escapeHtml(product.name)}" ${quantity >= product.quantity ? "disabled" : ""}>+</button>
    </div>
    <strong class="pos-line-total">${formatMoney(product.price * quantity)}</strong>
  </div>`).join("") : `<div class="pos-cart-empty">Your cart is empty.<br><span>Select a product to start a sale.</span></div>`;
  elements.posSubtotal.textContent = formatMoney(total);
  elements.posTotal.textContent = formatMoney(total);
  elements.posChange.textContent = formatMoney(validPayment ? cashReceived - total : 0);
  elements.posCheckout.disabled = unitCount === 0 || !validPayment;
  elements.posPaymentError.classList.toggle("hidden",
    elements.posCash.value.trim() === "" || validPayment || unitCount === 0);
  elements.posPaymentError.textContent = "Cash received must be at least the sale total.";
  elements.posSalesHistory.innerHTML = sales.slice(-6).reverse().map((sale) => `<tr>
    <td>${new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(sale.date))}</td>
    <td>${sale.items.map((item) => `${item.quantity}× ${escapeHtml(item.name)}`).join(", ")}</td>
    <td class="money-cell">${formatMoney(sale.total)}</td>
    <td>${formatMoney(sale.cashReceived)}</td>
    <td>${formatMoney(sale.change)}</td>
  </tr>`).join("") || `<tr><td class="table-empty" colspan="5">Completed sales will appear here.</td></tr>`;
}

function render() {
  renderDashboard();
  renderCatalog();
  renderPos();
}

function setView(view) {
  activeView = view;
  elements.overview.classList.toggle("hidden", view !== "overview");
  elements.products.classList.toggle("hidden", view !== "products");
  elements.pointOfSale.classList.toggle("hidden", view !== "pos");
  document.querySelectorAll(".nav-link").forEach((link) => link.classList.toggle("active", link.dataset.view === view));
  document.querySelector("#breadcrumb-current").textContent = { overview: "Overview", products: "Products", pos: "Point of sale" }[view] || "Overview";
  if (view === "products") elements.search.focus({ preventScroll: true });
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => elements.toast.classList.remove("visible"), 2800);
}

function openProductDialog(product) {
  elements.productForm.reset();
  elements.productError.classList.add("hidden");
  document.querySelector("#product-id").value = product ? product.id : "";
  document.querySelector("#product-dialog-title").textContent = product ? "Edit product" : "Add a product";
  document.querySelector("#product-submit").innerHTML = product ? "Save changes <span aria-hidden=\"true\">→</span>" : "Save product <span aria-hidden=\"true\">→</span>";
  if (product) {
    document.querySelector("#product-name").value = product.name;
    document.querySelector("#product-sku").value = product.sku;
    document.querySelector("#product-category").value = product.category;
    document.querySelector("#product-price").value = product.price;
    document.querySelector("#product-quantity").value = product.quantity;
    document.querySelector("#product-reorder").value = product.reorderLevel;
    document.querySelector("#product-location").value = product.location;
  } else {
    document.querySelector("#product-reorder").value = "5";
  }
  elements.productDialog.showModal();
  document.querySelector("#product-name").focus();
}

function openStockDialog(product, direction = "add") {
  elements.stockForm.reset();
  elements.stockError.classList.add("hidden");
  document.querySelector("#stock-product-id").value = product.id;
  document.querySelector("#stock-product-name").textContent = `${product.name} · ${product.sku}`;
  document.querySelector("#current-stock-value").textContent = product.quantity;
  document.querySelector(`input[name="adjustment"][value="${direction}"]`).checked = true;
  document.querySelector("#stock-dialog-title").textContent = direction === "remove" ? "Record sold items" : "Add stock";
  elements.stockDialog.showModal();
  document.querySelector("#stock-adjustment-quantity").focus();
}

function persistSale(updatedProducts, updatedSales) {
  const previousInventory = localStorage.getItem(STORAGE_KEY);
  const previousSales = localStorage.getItem(SALES_STORAGE_KEY);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updatedProducts));
    localStorage.setItem(SALES_STORAGE_KEY, JSON.stringify(updatedSales));
  } catch (error) {
    try {
      if (previousInventory === null) localStorage.removeItem(STORAGE_KEY);
      else localStorage.setItem(STORAGE_KEY, previousInventory);
      if (previousSales === null) localStorage.removeItem(SALES_STORAGE_KEY);
      else localStorage.setItem(SALES_STORAGE_KEY, previousSales);
    } catch (rollbackError) {
      console.error("Unable to roll back inventory after a failed sale.", rollbackError);
      throw new Error("The sale could not be saved and inventory could not be restored. Check browser storage before continuing.");
    }
    throw error;
  }
}

function completePosSale() {
  const total = cartTotal();
  const cashReceived = Math.round(Number(elements.posCash.value) * 100) / 100;
  if (cart.size === 0 || !Number.isFinite(cashReceived) || cashReceived < total) {
    renderPos();
    return;
  }

  const items = [];
  const quantities = new Map(cart);
  for (const [id, quantity] of quantities) {
    const product = products.find((item) => item.id === id);
    if (!product || !Number.isInteger(quantity) || quantity < 1 || quantity > product.quantity) {
      showToast("Cart stock changed. Review the cart before completing this sale.");
      renderPos();
      return;
    }
    items.push({ id: product.id, name: product.name, sku: product.sku, price: product.price, quantity });
  }

  const sale = {
    id: window.crypto?.randomUUID ? window.crypto.randomUUID() : `sale-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    date: new Date().toISOString(),
    items,
    total,
    cashReceived,
    change: Math.round((cashReceived - total) * 100) / 100
  };
  const updatedProducts = products.map((product) => ({
    ...product,
    quantity: product.quantity - (quantities.get(product.id) || 0)
  }));
  const updatedSales = [...sales, sale];

  try {
    persistSale(updatedProducts, updatedSales);
  } catch (error) {
    console.error("Unable to save the point-of-sale transaction.", error);
    showToast(error instanceof Error && error.message.startsWith("The sale could not be saved")
      ? error.message
      : "Could not save the sale. Check your browser storage and try again.");
    return;
  }

  products = updatedProducts;
  sales = updatedSales;
  cart.clear();
  elements.posCash.value = "";
  render();
  showToast(`Sale complete. Change: ${formatMoney(sale.change)}.`);
}

function exportCsv() {
  const columns = ["Name", "SKU", "Category", "Unit cost", "Quantity", "Reorder level", "Location", "Stock status"];
  const rows = products.map((product) => [product.name, product.sku, product.category, product.price.toFixed(2), product.quantity, product.reorderLevel, product.location, getStatus(product).label]);
  const csv = [columns, ...rows].map((row) => row.map((field) => `"${String(field).replace(/"/g, '""')}"`).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "scankwentory-inventory.csv";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast("Inventory exported as CSV.");
}

document.addEventListener("click", (event) => {
  const target = event.target instanceof Element ? event.target : null;
  if (!target) return;

  if (target.closest("[data-open-product]")) {
    openProductDialog(null);
  } else if (target.closest("[data-pos-add]")) {
    const product = products.find((item) => item.id === target.closest("[data-pos-add]").dataset.posAdd);
    if (product && (cart.get(product.id) || 0) < product.quantity) {
      cart.set(product.id, (cart.get(product.id) || 0) + 1);
      renderPos();
    }
  } else if (target.closest("[data-pos-increase], [data-pos-decrease]")) {
    const button = target.closest("[data-pos-increase], [data-pos-decrease]");
    const productId = button.dataset.posIncrease || button.dataset.posDecrease;
    const quantity = cart.get(productId) || 0;
    const product = products.find((item) => item.id === productId);
    if (button.hasAttribute("data-pos-increase") && product && quantity < product.quantity) {
      cart.set(productId, quantity + 1);
    } else if (button.hasAttribute("data-pos-decrease")) {
      if (quantity <= 1) cart.delete(productId);
      else cart.set(productId, quantity - 1);
    }
    renderPos();
  } else if (target.closest("#pos-clear-cart")) {
    cart.clear();
    elements.posCash.value = "";
    renderPos();
  } else if (target.closest("[data-view-products]")) {
    setView("products");
  } else if (target.closest("[data-show-low-stock]")) {
    setView("products");
    elements.search.value = "";
    elements.categoryFilter.value = "__low_stock__";
    renderCatalog();
  } else if (target.closest("[data-close-dialog]")) {
    target.closest("dialog")?.close();
  } else {
    const viewLink = target.closest("[data-view]");
    const adjustButton = target.closest("[data-adjust-stock]");
    const editButton = target.closest("[data-edit-product]");
    const deleteButton = target.closest("[data-delete-product]");
    if (viewLink) {
      event.preventDefault();
      setView(viewLink.dataset.view);
    } else if (adjustButton) {
      const product = products.find((item) => item.id === adjustButton.dataset.adjustStock);
      if (product) openStockDialog(product, adjustButton.dataset.stockDirection || "add");
    } else if (editButton) {
      const product = products.find((item) => item.id === editButton.dataset.editProduct);
      if (product) openProductDialog(product);
    } else if (deleteButton) {
      const product = products.find((item) => item.id === deleteButton.dataset.deleteProduct);
      if (product && window.confirm(`Delete "${product.name}" from your inventory? This cannot be undone.`)) {
        const previousProducts = products;
        products = products.filter((item) => item.id !== product.id);
        if (saveProducts()) {
          render();
          showToast(`${product.name} was deleted.`);
        } else {
          products = previousProducts;
        }
      }
    }
  }
});

document.querySelector("#product-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const id = document.querySelector("#product-id").value;
  const sku = String(form.get("sku")).trim();
  const existing = products.find((product) => product.sku.toLowerCase() === sku.toLowerCase() && product.id !== id);
  if (existing) {
    elements.productError.textContent = "That SKU is already in use. Each product needs a unique SKU.";
    elements.productError.classList.remove("hidden");
    document.querySelector("#product-sku").focus();
    return;
  }

  const product = {
    id: id || (window.crypto?.randomUUID ? window.crypto.randomUUID() : `item-${Date.now()}-${Math.random().toString(16).slice(2)}`),
    name: String(form.get("name")).trim(),
    sku,
    category: String(form.get("category")).trim(),
    price: Number(form.get("price")),
    quantity: Number(form.get("quantity")),
    reorderLevel: form.get("reorderLevel") === "" ? 5 : Number(form.get("reorderLevel")),
    location: String(form.get("location")).trim()
  };
  if (!isValidProduct(product) || !product.name || !product.sku || !product.category || !Number.isFinite(product.price)) {
    elements.productError.textContent = "Check the product details and enter valid non-negative amounts.";
    elements.productError.classList.remove("hidden");
    return;
  }

  const previousProducts = products;
  products = id ? products.map((item) => item.id === id ? product : item) : [...products, product];
  if (!saveProducts()) {
    products = previousProducts;
    return;
  }
  elements.productDialog.close();
  render();
  showToast(id ? "Product details updated." : "Product added to your inventory.");
});

document.querySelector("#stock-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const id = document.querySelector("#stock-product-id").value;
  const product = products.find((item) => item.id === id);
  const quantity = Number(document.querySelector("#stock-adjustment-quantity").value);
  const direction = new FormData(event.currentTarget).get("adjustment");
  if (!product || !Number.isInteger(quantity) || quantity < 1) {
    elements.stockError.textContent = "Enter a whole quantity greater than zero.";
    elements.stockError.classList.remove("hidden");
    return;
  }
  if (direction === "remove" && quantity > product.quantity) {
    elements.stockError.textContent = `Only ${product.quantity} units are currently in stock.`;
    elements.stockError.classList.remove("hidden");
    return;
  }
  const updated = { ...product, quantity: product.quantity + (direction === "add" ? quantity : -quantity) };
  products = products.map((item) => item.id === id ? updated : item);
  if (!saveProducts()) {
    products = products.map((item) => item.id === id ? product : item);
    return;
  }
  elements.stockDialog.close();
  render();
  showToast(direction === "remove"
    ? `${quantity} ${quantity === 1 ? "item" : "items"} recorded as sold. ${updated.quantity} left in stock.`
    : `${quantity} ${quantity === 1 ? "unit" : "units"} added. ${updated.quantity} now in stock.`);
});

elements.posSearch.addEventListener("input", renderPos);
elements.posCash.addEventListener("input", renderPos);
elements.posCheckout.addEventListener("click", completePosSale);

elements.authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  elements.authError.classList.add("hidden");
  elements.authSubmit.disabled = true;
  elements.authSubmit.textContent = setupMode ? "Creating account…" : "Signing in…";

  try {
    const email = elements.authEmail.value.trim().toLowerCase();
    const password = elements.authPassword.value;
    let signedInAccount;

    if (setupMode) {
      const name = elements.authName.value.trim();
      if (!name || password.length < 8) {
        throw new Error("Enter your name and choose a password with at least 8 characters.");
      }
      if (accounts.some((user) => user.email.toLowerCase() === email)) {
        throw new Error("An account with this email already exists. Choose Sign in instead.");
      }
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      signedInAccount = {
        name,
        email,
        salt: bytesToHex(salt),
        passwordHash: await hashPassword(password, salt)
      };
      const updatedAccounts = [...accounts, signedInAccount];
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(updatedAccounts));
      accounts = updatedAccounts;
    } else {
      signedInAccount = accounts.find((user) => user.email.toLowerCase() === email);
      if (!signedInAccount) {
        throw new Error("Email or password is incorrect.");
      }
      const salt = Uint8Array.from(signedInAccount.salt.match(/.{2}/g).map((byte) => Number.parseInt(byte, 16)));
      const attemptedHash = await hashPassword(password, salt);
      let difference = attemptedHash.length ^ signedInAccount.passwordHash.length;
      for (let index = 0; index < Math.max(attemptedHash.length, signedInAccount.passwordHash.length); index += 1) {
        difference |= (attemptedHash.charCodeAt(index) || 0) ^ (signedInAccount.passwordHash.charCodeAt(index) || 0);
      }
      if (difference !== 0) {
        throw new Error("Email or password is incorrect.");
      }
    }

    sessionStorage.setItem(AUTH_SESSION_KEY, signedInAccount.email.toLowerCase());
    elements.authForm.reset();
    showInventory(signedInAccount);
  } catch (error) {
    console.error("Local sign-in failed.", error);
    if (error instanceof Error && (
      error.message.startsWith("Email or password") ||
      error.message.startsWith("Enter your name") ||
      error.message.startsWith("An account with this email")
    )) {
      elements.authError.textContent = error.message;
    } else if (error instanceof Error && error.message.startsWith("Secure password hashing")) {
      elements.authError.textContent = error.message;
    } else {
      elements.authError.textContent = "Unable to save or restore your local sign-in. Check that browser storage is enabled and try again.";
    }
    elements.authError.classList.remove("hidden");
  } finally {
    elements.authSubmit.disabled = false;
    elements.authSubmit.innerHTML = setupMode ? "Create account <span aria-hidden=\"true\">→</span>" : "Sign in <span aria-hidden=\"true\">→</span>";
  }
});

elements.authSwitchButton.addEventListener("click", () => {
  setAuthMode(!setupMode);
  elements.authError.classList.add("hidden");
  elements.authForm.reset();
  (setupMode ? elements.authName : elements.authEmail).focus();
});

elements.authPasswordToggle.addEventListener("click", () => {
  const isVisible = elements.authPassword.type === "password";
  setPasswordVisibility(isVisible);
});

elements.logoutButton.addEventListener("click", () => {
  try {
    sessionStorage.removeItem(AUTH_SESSION_KEY);
  } catch (error) {
    console.error("Unable to clear the local sign-in session.", error);
    showToast("Could not log out. Browser session storage is unavailable.");
    return;
  }
  elements.appShell.classList.add("hidden");
  elements.authScreen.classList.remove("hidden");
  elements.authForm.reset();
  elements.authError.classList.add("hidden");
  setAuthMode(false);
  elements.authEmail.focus();
});

elements.search.addEventListener("input", renderCatalog);
elements.categoryFilter.addEventListener("change", renderCatalog);
document.querySelector("#export-button").addEventListener("click", exportCsv);
document.addEventListener("keydown", (event) => {
  if (event.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName) && activeView === "products") {
    event.preventDefault();
    elements.search.focus();
  }
});

const date = new Date();
document.querySelector("#today-label").textContent = new Intl.DateTimeFormat(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" }).format(date);
document.querySelector("#footer-year").textContent = date.getFullYear();
document.querySelector("#footer-year-products").textContent = date.getFullYear();
document.querySelector("#footer-year-pos").textContent = date.getFullYear();
initializeAuth();
