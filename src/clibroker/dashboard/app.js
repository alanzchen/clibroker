/* Same-origin browser client. Credentials stay in memory; optional control history lives on the server. */
"use strict";
const $ = (id) => document.getElementById(id);
const I18n = window.DashboardI18n;
const apiBase = new URL("../", document.currentScript.src);
let savedLanguage = null;
try { savedLanguage = localStorage.getItem(I18n.preferenceKey); } catch { /* Storage may be unavailable. */ }
let language = I18n.detectLanguage(navigator.languages || [navigator.language], savedLanguage);
let token = "";
let config = null;
let selectedTool = null;
let activity = [];
let lastResult = null;
let noticeState = null;
const formErrors = new Map();
let generation = 0;
let executing = false;
let connecting = false;
let controlData = null;
let controlBusy = false;
let controlLoading = false;
let controlTimer = null;
let controlVersion = 0;
let controlError = null;
let currentRequest = null;
let requestGeneration = 0;
let historyQuery = "";
let historyState = "";
let agentsSignature = null;
let pendingSignature = null;
let activitySignature = null;
let requestSignature = null;
let resultSignature = null;
const controlEnabled = () => Boolean(config?.control?.enabled);
const isOwner = () => config?.control?.role === "owner";

const message = (key, values = {}) => ({ key, values });
function text(value) {
  if (typeof value === "string") return value; // Server-owned labels remain unchanged.
  const values = Object.fromEntries(Object.entries(value.values).map(([key, item]) => [key,
    item && typeof item === "object" && item.key ? text(item) : item,
  ]));
  return I18n.text(language, value.key, values);
}
const t = (key, values) => text(message(key, values));
class DashboardError extends Error {
  constructor(key, values) { super(key); this.translation = message(key, values); }
}
const failure = (error) => error.translation || message("unexpectedError");
function element(tag, content, className) {
  const node = document.createElement(tag);
  if (content !== undefined) node.textContent = text(content);
  if (className) node.className = className;
  return node;
}
function bindText(node, content) {
  if (typeof content === "string") node.textContent = content;
  else {
    node.dataset.i18n = content.key;
    node.i18nValues = content.values;
    node.textContent = text(content);
  }
  return node;
}
function translatedElement(tag, key, values, className) {
  return bindText(element(tag, undefined, className), message(key, values));
}
function renderMessages() {
  $("notice").textContent = noticeState ? text(noticeState.content) : "";
  $("notice").className = noticeState?.error ? "notice error" : "notice";
  $("notice").hidden = !noticeState;
  for (const id of ["connect-error", "execute-error", "review-error"]) {
    const content = formErrors.get(id);
    $(id).textContent = content ? text(content) : "";
    $(id).hidden = !content;
  }
}
function notice(content, error = false) {
  noticeState = content ? { content, error } : null;
  renderMessages();
}
function formError(id, content) {
  formErrors.set(id, content);
  renderMessages();
}
function applyLanguage(next, persist = false) {
  language = Object.hasOwn(I18n.locales, next) ? next : "en";
  if (persist) {
    try { localStorage.setItem(I18n.preferenceKey, language); } catch { /* Memory-only fallback. */ }
  }
  document.documentElement.lang = language;
  document.title = t("pageTitle");
  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.dataset.i18n, node.i18nValues);
  }
  for (const attribute of ["aria-label", "placeholder"]) {
    for (const node of document.querySelectorAll(`[data-i18n-${attribute}]`)) {
      node.setAttribute(attribute, t(node.getAttribute(`data-i18n-${attribute}`)));
    }
  }
  for (const select of document.querySelectorAll("[data-language]")) select.value = language;
  // Translate the existing form in place. Never rebuild its inputs on a locale change.
  render();
}
function apiUrl(path) {
  const url = new URL(path.replace(/^\//, ""), apiBase);
  if (url.origin !== apiBase.origin || !url.pathname.startsWith(apiBase.pathname) || url.username || url.password) throw new DashboardError("invalidEndpoint");
  return url;
}
async function request(path, credential, body, method = body ? "POST" : "GET") {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120000);
  try {
    const response = await fetch(apiUrl(path), {
      method,
      headers: { Authorization: `Bearer ${credential}`, ...(body ? { "Content-Type": "application/json" } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
      credentials: "omit", cache: "no-store", redirect: "error", signal: controller.signal,
    });
    if (response.status === 401) throw new DashboardError("invalidCredential");
    if (response.status === 403) throw new DashboardError("forbidden");
    if (!response.ok) throw new DashboardError("httpError", { status: response.status });
    return await response.json();
  } catch (error) {
    if (error.name === "AbortError") throw new DashboardError("timeoutError");
    if (error instanceof TypeError) throw new DashboardError("networkError");
    throw error;
  } finally { clearTimeout(timeout); }
}
function openConnection() {
  if (executing || connecting || controlBusy) return;
  $("token").value = "";
  formError("connect-error", null);
  $("connect-dialog").showModal();
  $("token").focus();
}
function render() {
  const connected = Boolean(config);
  $("setup-steps").hidden = connected;
  $("overview-hero").classList.toggle("connected-hero", connected);
  $("assistant-setup-title").textContent = t(isOwner() ? "ownerSetupTitle" : "assistantReuse");
  $("assistant-setup-help").textContent = t(isOwner() ? "ownerSetupHelp" : "assistantInstructions");
  $("copy-mcp").hidden = isOwner();
  $("connection-label").textContent = t(connected ? "connected" : "disconnected");
  $("connection-dot").classList.toggle("online", connected);
  $("connect-button").textContent = t(connected ? "switchConnection" : "connectService");
  $("connect-button").disabled = executing || connecting || controlBusy;
  $("refresh-button").disabled = !connected || executing || connecting || controlBusy;
  $("disconnect-button").disabled = !connected || executing || connecting || controlBusy;
  $("copy-mcp").disabled = !connected || isOwner();
  $("clear-activity").disabled = !activity.length || executing;
  $("connect-submit").disabled = connecting;
  $("connect-submit").textContent = t(connecting ? "connecting" : "connect");
  $("execute-submit").disabled = executing || controlBusy || !selectedRule();
  $("execute-submit").textContent = t(executing ? "executing" : "execute");
  $("client-name").textContent = connected ? config.client_name : t("waitingConnection");
  $("client-summary").textContent = connected ? t("clientSummary", { count: config.tools.length }) : t("clientWaiting");
  $("tools-subtitle").textContent = t(connected ? "visibleTools" : "toolsWaiting");
  $("tools").replaceChildren();
  if (!connected) {
    const empty = element("div", undefined, "empty");
    empty.append(element("span", "▤", "empty-icon"), element("h3", message("emptyTitle")), element("p", message("emptyDescription")));
    const button = element("button", message("connectService"), "button primary");
    button.addEventListener("click", openConnection);
    empty.append(button, element("p", message("localSetup"), "fine-print"), element("code", "clibroker init --directory ./clibroker-local", "setup-command"), element("p", message("localSetupCredentials"), "fine-print"));
    $("tools").append(empty);
  } else {
    if (!config.tools.length) $("tools").append(element("p", message("noTools"), "empty-line"));
    for (const tool of config.tools) {
      const card = element("article", undefined, "tool-card");
      const symbol = element("span", "▤", "tool-symbol");
      symbol.setAttribute("aria-hidden", "true");
      const description = element("div", undefined, "tool-text");
      description.append(element("h3", tool.title || tool.name), element("p", message("toolCounts", { operations: tool.rules.length, shares: tool.file_shares.length })));
      if (tool.description) description.append(element("p", tool.description));
      const button = element("button", message("viewOperations"), "button secondary");
      button.setAttribute("aria-label", t("viewOperationsAria", { tool: tool.name }));
      button.disabled = executing || connecting || controlBusy;
      button.addEventListener("click", () => openTool(tool));
      card.append(symbol, description, button);
      $("tools").append(card);
    }
  }
  renderActivity();
  renderMessages();
  renderResult();
  renderControl();
  renderPreview();
}
function renderActivity() {
  const signature = JSON.stringify([language, controlEnabled(), historyQuery, historyState, controlData?.activity, activity]);
  if (signature === activitySignature) return;
  activitySignature = signature;
  $("activity").replaceChildren();
  $("history-filters").hidden = !controlEnabled();
  $("clear-activity").hidden = controlEnabled();
  $("activity-scope").textContent = t(controlEnabled() ? "durableScope" : "activityScope");
  if (controlEnabled()) {
    const rows = filterHistory(controlData?.activity || [], historyQuery, historyState);
    if (!rows.length) $("activity").append(element("p", message("noMatches"), "empty-line"));
    for (const item of rows) $("activity").append(requestRow(item));
    return;
  }
  if (!activity.length) $("activity").append(element("p", message("activityEmpty"), "empty-line"));
  for (const item of activity) {
    const row = element("div", undefined, "activity-row");
    const icon = element("span", item.ok ? "✓" : "!", item.ok ? "activity-icon" : "activity-icon failed");
    icon.setAttribute("aria-hidden", "true");
    const description = element("div");
    description.append(element("h3", `${item.tool} · ${item.command}`), element("p", item.summary));
    const time = element("time", item.date.toLocaleTimeString(language, { hour: "2-digit", minute: "2-digit" }));
    time.dateTime = item.date.toISOString();
    time.title = item.date.toLocaleString(language);
    row.append(icon, description, time);
    $("activity").append(row);
  }
}
function resultSummary(result) {
  return message(result.state === "pending" ? "statePending" : result.ok ? "completed" : result.timed_out ? "resultTimedOut" : "notCompleted");
}
function renderResult() {
  const signature = JSON.stringify([language, isOwner(), lastResult]);
  if (signature === resultSignature) return;
  resultSignature = signature;
  $("result-section").hidden = !lastResult;
  $("result-artifacts").replaceChildren();
  if (!lastResult) { $("result").textContent = ""; $("result-json").textContent = ""; return; }
  const result = lastResult;
  const stdout = typeof result.stdout === "string" ? result.stdout : JSON.stringify(result.stdout, null, 2);
  $("result-title").textContent = text(resultSummary(result));
  $("result").textContent = [t("exitCode", { code: result.exit_code }), t("duration", {
    milliseconds: new Intl.NumberFormat(language).format(Math.round(result.duration_ms)),
  }), "", t("output"), stdout || t("none"), "", t("errorOutput"), result.stderr || t("none")].join("\n");
  $("result-json").textContent = JSON.stringify(result, null, 2);
  if (result.state === "pending") {
    $("result").textContent = t("requestPendingHelp");
    const review = element("button", message(isOwner() ? "review" : "details"), "button secondary");
    review.addEventListener("click", () => openRequest(result.request_id));
    $("result-artifacts").append(review);
  }
  appendArtifacts($("result-artifacts"), result.artifacts || []);
}
function selectedRule() { return selectedTool?.rules[Number($("operation").value)]; }
function addInput(label, id, { enumValues, help = [], checkbox = false } = {}) {
  const wrapper = element("div");
  const field = element(enumValues ? "select" : "input");
  field.id = id;
  if (enumValues) {
    const placeholder = translatedElement("option", "choose");
    placeholder.value = "";
    field.append(placeholder);
    for (const value of enumValues) field.append(new Option(value, value));
  } else field.type = checkbox ? "checkbox" : "text";
  field.autocomplete = "off";
  const caption = element("label", undefined, checkbox ? "check-row" : undefined);
  caption.htmlFor = id;
  if (checkbox) { caption.append(field, document.createTextNode(text(label))); wrapper.append(caption); }
  else { bindText(caption, label); wrapper.append(caption, field); }
  const hints = [];
  help.filter(Boolean).forEach((content, index) => {
    const hint = bindText(element("p", undefined, "field-help"), content);
    hint.id = `${id}-help-${index}`;
    hints.push(hint.id);
    wrapper.append(hint);
  });
  if (hints.length) field.setAttribute("aria-describedby", hints.join(" "));
  $("parameters").append(wrapper);
  return field;
}
function renderParameters() {
  $("parameters").replaceChildren();
  $("confirm-execution").checked = false;
  $("extra-args").value = "";
  lastResult = null;
  formError("execute-error", null);
  const rule = selectedRule();
  $("extra-details").open = Boolean(rule?.allow_any_args);
  bindText($("extra-args-label"), message(rule?.allow_any_args ? "rawArguments" : "extraArguments"));
  bindText($("extra-summary"), message(rule?.allow_any_args ? "enterRawArguments" : "moreArguments"));
  if (!rule) $("parameters").append(translatedElement("p", "noOperations", {}, "field-help"));
  else {
    rule.command.forEach((part, index) => {
      if (part === "*") addInput(message("commandSegment", { number: index + 1 }), `command-${index}`, { help: [message("commandHelp")] }).required = true;
    });
    if (selectedTool.argv_normalization?.patterns.length) addInput(message("globalArguments"), "global-args", { help: [message("globalHelp")] });
    rule.positionals.forEach((pos, index) => addInput(
      pos.variadic ? message("manyValues", { name: pos.name }) : pos.name, `pos-${index}`, {
        enumValues: pos.variadic ? null : pos.enum,
        help: [message(pos.variadic ? "variadicHelp" : "positionalHelp"),
          pos.pattern && message("patternHelp", { pattern: pos.pattern }),
          pos.variadic && pos.enum && message("enumHelp", { values: pos.enum.join(", ") })],
      },
    ).required = true);
    rule.flags.forEach((flag, index) => addInput(flag, `flag-${index}`, { help: [message("optionalFlag")] }));
    rule.standalone_flags.forEach((flag, index) => addInput(flag, `switch-${index}`, { checkbox: true }));
  }
  render();
}
function openTool(tool) {
  if (executing || connecting || controlBusy) return;
  selectedTool = tool;
  $("tool-title").textContent = tool.title || tool.name;
  $("operation").replaceChildren();
  tool.rules.forEach((rule, index) => $("operation").append(new Option(rule.title || `${rule.command.join(" ")} (${rule.id})`, String(index))));
  $("operation").disabled = !tool.rules.length;
  renderParameters();
  $("tool-dialog").showModal();
}
function stringArray(value, label) {
  let parsed;
  try { parsed = JSON.parse(value); } catch { throw new DashboardError("jsonArrayError", { label }); }
  if (!Array.isArray(parsed) || parsed.some((part) => typeof part !== "string")) throw new DashboardError("stringArrayError", { label });
  return parsed;
}
function buildArgv(rule) {
  const globalArgs = $("global-args")?.value.trim();
  const argv = globalArgs ? stringArray(globalArgs, message("globalArguments")) : [];
  argv.push(...rule.command.map((part, index) => {
    if (part !== "*") return part;
    const value = $(`command-${index}`).value.trim();
    if (!value) throw new DashboardError("missingCommand");
    return value;
  }));
  rule.flags.forEach((flag, index) => {
    const value = $(`flag-${index}`).value;
    if (value !== "") argv.push(flag, value);
  });
  rule.standalone_flags.forEach((flag, index) => { if ($(`switch-${index}`).checked) argv.push(flag); });
  const positionals = [];
  rule.positionals.forEach((pos, index) => {
    const value = $(`pos-${index}`).value;
    const values = pos.variadic ? stringArray(value.trim() || "[]", pos.name) : value === "" ? [] : [value];
    if (!values.length) throw new DashboardError(pos.variadic ? "variadicRequired" : "requiredArgument", { name: pos.name });
    positionals.push(...values);
  });
  const extra = $("extra-args").value.trim() ? stringArray($("extra-args").value, message("extraArguments")) : [];
  if (positionals.some((value) => value.startsWith("-"))) {
    // Keep extra options before the boundary, but preserve the positional tail's order.
    const tail = [];
    for (let index = 0; index < extra.length; index += 1) {
      const arg = extra[index];
      if (arg === "--") { tail.push(...extra.slice(index + 1)); break; }
      if (!arg.startsWith("-")) { tail.push(arg); continue; }
      // Unknown options stay on the option side so server policy still rejects them.
      argv.push(arg);
      if (rule.flags.includes(arg) && index + 1 < extra.length) argv.push(extra[++index]);
    }
    argv.push("--", ...positionals, ...tail);
  } else argv.push(...positionals, ...extra);
  return argv;
}
function executionBusy(busy) {
  for (const field of $("execute-form").querySelectorAll("input, select, textarea, button")) field.disabled = busy;
  document.querySelector('#tool-dialog .icon-button').disabled = busy;
}
for (const select of document.querySelectorAll("[data-language]")) {
  for (const [code, name] of Object.entries(I18n.locales)) select.append(new Option(name, code));
  select.addEventListener("change", () => applyLanguage(select.value, true));
}
$("connect-button").addEventListener("click", openConnection);
for (const button of document.querySelectorAll("[data-close]")) button.addEventListener("click", () => {
  if (!executing && !connecting && !controlBusy) $(button.dataset.close).close();
});
for (const dialog of document.querySelectorAll("dialog")) dialog.addEventListener("cancel", (event) => {
  if (executing || connecting || controlBusy) event.preventDefault();
});
$("connect-dialog").addEventListener("close", () => { $("token").value = ""; });
$("tool-dialog").addEventListener("close", () => {
  selectedTool = null;
  lastResult = null;
  $("parameters").replaceChildren();
  $("extra-args").value = "";
  formError("execute-error", null);
  renderResult();
});
$("connect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (connecting || executing || controlBusy) return;
  const credential = $("token").value.trim();
  if (!credential) { formError("connect-error", message("credentialRequired")); return; }
  connecting = true;
  formError("connect-error", null);
  render();
  try {
    const next = await request("client-config", credential);
    token = credential;
    config = next;
    generation += 1;
    activity = [];
    resetControl();
    $("connect-dialog").close();
    if (controlEnabled()) {
      refreshControl();
      const linked = new URL(window.location.href).searchParams.get("request");
      if (linked && /^[A-Za-z0-9_-]{1,128}$/.test(linked)) openRequest(linked);
    }
    notice(message("connectedNotice"));
  } catch (error) { formError("connect-error", failure(error)); }
  finally { connecting = false; render(); }
});
$("disconnect-button").addEventListener("click", () => {
  if (executing || connecting || controlBusy) return;
  generation += 1;
  resetControl();
  token = "";
  config = null;
  selectedTool = null;
  lastResult = null;
  activity = [];
  $("parameters").replaceChildren();
  $("token").value = "";
  notice(message("disconnectedNotice"));
  render();
});
$("refresh-button").addEventListener("click", async () => {
  if (!token || executing || connecting) return;
  const current = generation;
  $("refresh-button").disabled = true;
  try {
    const next = await request("client-config", token);
    if (generation !== current) return;
    config = next;
    notice(message("refreshed"));
    if (controlEnabled()) refreshControl();
  } catch (error) { if (generation === current) notice(failure(error), true); }
  finally { render(); }
});
$("copy-mcp").addEventListener("click", async () => {
  if (!config || isOwner()) return;
  const current = generation;
  let url;
  try {
    url = apiUrl(config.mcp_url);
  } catch { notice(message("invalidEndpoint"), true); return; }
  try {
    await navigator.clipboard.writeText(url.href);
    if (generation === current) notice(message("copied"));
  } catch { if (generation === current) notice(message("copyManually", { url: url.href })); }
});
$("operation").addEventListener("change", renderParameters);
$("execute-form").addEventListener("input", (event) => {
  if (event.target !== $("confirm-execution")) $("confirm-execution").checked = false;
  renderPreview();
});
$("execute-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const rule = selectedRule();
  if (!rule || executing || controlBusy || !token) return;
  formError("execute-error", null);
  if (!$("confirm-execution").checked) { formError("execute-error", message("confirmRequired")); return; }
  let argv;
  try { argv = buildArgv(rule); } catch (error) { formError("execute-error", failure(error)); return; }
  const tool = selectedTool.name;
  const item = { tool, command: rule.command.join(" "), date: new Date(), ok: false };
  executing = true;
  lastResult = null;
  executionBusy(true);
  render();
  try {
    lastResult = await request("execute", token, { tool, argv });
    item.ok = lastResult.ok;
    item.summary = resultSummary(lastResult);
  } catch (error) {
    item.summary = failure(error);
    formError("execute-error", item.summary);
  } finally {
    activity.unshift(item);
    activity = activity.slice(0, 30);
    executing = false;
    executionBusy(false);
    $("confirm-execution").checked = false;
    render();
    if (controlEnabled()) refreshControl();
  }
});
$("clear-activity").addEventListener("click", () => { activity = []; render(); });


function stateLabel(state) {
  const keys = { succeeded: "stateSucceeded", pending: "statePending", failed: "stateFailed", blocked: "stateBlocked", rejected: "stateRejected", expired: "stateExpired", running: "stateRunning", interrupted: "stateInterrupted" };
  return t(keys[state] || "notCompleted");
}
function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(language, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function filterHistory(rows, query, outcome) {
  const needle = query.trim().toLocaleLowerCase();
  return rows.filter(item => (!outcome || item.state === outcome) && (!needle || [item.client, item.tool, item.rule_id].join(" ").toLocaleLowerCase().includes(needle)));
}
function renderPreview() {
  const rule = selectedRule();
  $("operation-description").textContent = rule?.description || "";
  if (!rule) { $("argv-preview").textContent = ""; return; }
  try { $("argv-preview").textContent = JSON.stringify({ tool: selectedTool.name, argv: buildArgv(rule) }, null, 2); }
  catch { $("argv-preview").textContent = t("previewIncomplete"); }
}
function resetControl() {
  if (controlTimer) clearTimeout(controlTimer);
  controlTimer = null;
  controlData = null;
  controlVersion += 1;
  controlLoading = false;
  controlError = null;
  currentRequest = null;
  agentsSignature = pendingSignature = activitySignature = requestSignature = resultSignature = null;
  expandedAgents.clear();
  $("agents").replaceChildren();
  $("pending-requests").replaceChildren();
  requestGeneration += 1;
  historyQuery = "";
  historyState = "";
  $("activity-search").value = "";
  $("activity-state").value = "";
  $("request-dialog").close();
  $("request-detail").replaceChildren();
}
async function refreshControl() {
  if (!token || !controlEnabled() || controlBusy || controlLoading) return;
  if (controlTimer) clearTimeout(controlTimer);
  const current = generation;
  const version = ++controlVersion;
  controlLoading = true;
  renderControl();
  try {
    const next = await request("control", token);
    if (generation !== current) return;
    if (controlVersion !== version) return;
    controlData = next;
    controlError = null;
    if (currentRequest) {
      const updated = [...(next.requests || []), ...(next.activity || [])].find(item => item.id === currentRequest.id);
      if (updated) {
        if (updated.state !== currentRequest.state && updated.state !== "pending") {
          const selection = requestGeneration;
          const full = await request(`control/requests/${encodeURIComponent(updated.id)}`, token);
          if (generation !== current || controlVersion !== version) return;
          if (requestGeneration === selection && currentRequest?.id === updated.id) currentRequest = full;
        } else currentRequest = { ...updated, result: currentRequest.result };
      }
    }
    if (lastResult?.state === "pending") {
      const updated = (next.activity || []).find(item => item.id === lastResult.request_id);
      if (updated && updated.state !== "pending") {
        const full = await request(`control/requests/${encodeURIComponent(updated.id)}`, token);
        if (generation !== current || controlVersion !== version) return;
        if (lastResult?.request_id === updated.id && full.result) lastResult = full.result;
      }
    }
  } catch (error) {
    if (generation === current && controlVersion === version) controlError = failure(error);
  } finally {
    if (generation === current && controlVersion === version) {
      controlLoading = false;
      renderControl(); renderActivity(); renderResult();
      if (controlEnabled()) controlTimer = setTimeout(() => {
        if (!document.hidden) refreshControl();
      }, 5000);
    }
  }
}
function visibleRule(id, client) {
  return config?.tools.flatMap(tool => tool.rules).find(rule => rule.id === id)
    || controlData?.agents?.find(agent => agent.name === client)?.rules.find(rule => rule.id === id);
}
function requestRow(item) {
  const row = element("article", undefined, "request-row");
  const status = element("span", stateLabel(item.state), `state-badge state-${item.state}`);
  const content = element("div", undefined, "request-copy");
  const rule = visibleRule(item.rule_id, item.client);
  content.append(element("h3", rule?.title || item.rule_id || item.tool), element("p", message("requestFrom", { agent: item.client, tool: item.tool })));
  const meta = element("div", undefined, "request-meta");
  meta.append(status, element("time", formatTime(item.created_at)));
  const action = element("button", message(item.state === "pending" && isOwner() ? "review" : "details"), "button secondary");
  action.disabled = controlBusy;
  action.addEventListener("click", () => openRequest(item.id));
  row.append(content, meta, action);
  return row;
}
function renderControl() {
  const enabled = controlEnabled();
  $("control-section").hidden = !enabled;
  $("agents-section").hidden = !enabled || !isOwner();
  $("agents-nav").hidden = !enabled || !isOwner();
  if (!enabled) return;
  $("control-refresh").disabled = controlLoading || controlBusy;
  $("control-summary").textContent = t(controlLoading && !controlData ? "controlLoading" : isOwner() ? "controlOwnerSummary" : "controlAgentSummary");
  $("control-error").textContent = controlError ? `${t("controlUnavailable")} ${text(controlError)}` : "";
  $("control-error").hidden = !controlError;
  const pending = (controlData?.requests || []).filter(item => item.state === "pending");
  $("pending-count").textContent = String(pending.length);
  $("recent-count").textContent = String(controlData?.activity?.length || 0);
  $("access-mode").textContent = t(isOwner() ? "owner" : "agent");
  const signature = JSON.stringify([language, isOwner(), pending, Boolean(controlData), controlBusy]);
  if (signature !== pendingSignature) {
  pendingSignature = signature;
  $("pending-requests").replaceChildren();
  if (!controlData) $("pending-requests").append(element("p", message("controlLoading"), "empty-line"));
  else if (!pending.length) {
    const empty = element("div", undefined, "all-clear");
    empty.append(element("span", "✓", "all-clear-icon"), element("h3", message("nothingPending")), element("p", message("nothingPendingHelp")));
    $("pending-requests").append(empty);
  } else for (const item of pending) $("pending-requests").append(requestRow(item));
  }
  renderAgents();
  if (currentRequest) renderRequest();
}
function renderAgents() {
  const signature = JSON.stringify([language, isOwner(), controlBusy, controlData?.agents]);
  if (signature === agentsSignature) return;
  agentsSignature = signature;
  $("agents").replaceChildren();
  if (!isOwner()) return;
  const agents = controlData?.agents || [];
  if (!agents.length) $("agents").append(element("p", message("noAgents"), "empty-line"));
  for (const agent of agents) {
    const card = element("details", undefined, "agent-card");
    // Expanded state follows the agent across refreshes without storing sensitive data.
    card.open = expandedAgents.has(agent.name);
    card.addEventListener("toggle", () => { if (card.open) expandedAgents.add(agent.name); else expandedAgents.delete(agent.name); });
    const summary = element("summary");
    summary.append(element("span", agent.name, "agent-name"), element("span", message(agent.paused ? "paused" : "active"), `state-badge ${agent.paused ? "state-blocked" : "state-succeeded"}`));
    card.append(summary);
    const controls = element("div", undefined, "agent-controls");
    const pause = element("button", message(agent.paused ? "resume" : "pause"), "button secondary");
    pause.disabled = controlBusy;
    pause.addEventListener("click", () => changeControl(`control/agents/${encodeURIComponent(agent.name)}`, { paused: !agent.paused }, "PATCH"));
    controls.append(pause);
    card.append(controls);
    if (!agent.rules.length) card.append(element("p", message("noAgentRules"), "empty-line"));
    for (const rule of agent.rules) {
      const row = element("div", undefined, "rule-row");
      const desc = element("div");
      desc.append(element("h3", rule.title || rule.id), element("p", rule.description || rule.tool));
      if (rule.requires_approval) desc.append(element("p", message("approvalRequired"), "fine-print"));
      const choices = element("div", undefined, "rule-choices");
      choices.setAttribute("role", "group");
      choices.setAttribute("aria-label", t("ruleAccess", { rule: rule.title || rule.id, agent: agent.name }));
      for (const decision of ["allow", "ask", "block"]) {
        const button = element("button", message(decision), `rule-choice decision-${decision}`);
        button.setAttribute("aria-pressed", String(rule.decision === decision));
        button.disabled = controlBusy || rule.decision === decision || (decision === "allow" && rule.requires_approval);
        button.addEventListener("click", () => changeControl(`control/agents/${encodeURIComponent(agent.name)}/rules/${encodeURIComponent(rule.id)}`, { decision }, "PUT"));
        choices.append(button);
      }
      row.append(desc, choices); card.append(row);
    }
    $("agents").append(card);
  }
}
const expandedAgents = new Set();
async function changeControl(path, body, method) {
  if (controlBusy || !isOwner() || !token) return;
  const current = generation;
  controlBusy = true;
  controlVersion += 1; controlLoading = false;
  render();
  try {
    await request(path, token, body, method);
    if (generation === current) notice(message("saved"));
  } catch (error) { if (generation === current) notice(failure(error), true); }
  finally {
    if (generation === current) {
      controlBusy = false; render();
      await refreshControl();
    }
  }
}
async function openRequest(id) {
  if (!id || !token || controlBusy) return;
  const current = generation;
  const opening = ++requestGeneration;
  try {
    const item = await request(`control/requests/${encodeURIComponent(id)}`, token);
    if (generation !== current || opening !== requestGeneration) return;
    currentRequest = item;
    formError("review-error", null);
    renderRequest();
    if (!$("request-dialog").open) $("request-dialog").showModal();
  } catch (error) { if (generation === current && opening === requestGeneration) notice(failure(error), true); }
}
function renderRequest() {
  if (!currentRequest) return;
  const item = currentRequest;
  const signature = JSON.stringify([language, isOwner(), controlBusy, item]);
  if (signature === requestSignature) return;
  requestSignature = signature;
  const rule = visibleRule(item.rule_id, item.client);
  $("request-title").textContent = rule?.title || item.rule_id || item.tool;
  const detail = $("request-detail"); detail.replaceChildren();
  detail.append(element("span", stateLabel(item.state), `state-badge state-${item.state}`), element("p", message("requestFrom", { agent: item.client, tool: item.tool })), element("p", message("requestedAt", { time: formatTime(item.created_at) })));
  if (item.state === "pending") detail.append(element("p", message("expiresAt", { time: formatTime(item.expires_at) })));
  if (item.decided_by) detail.append(element("p", message("decidedBy", { owner: item.decided_by, time: formatTime(item.decided_at) })));
  detail.append(element("h3", message("requestPreview")), element("pre", JSON.stringify({ tool: item.tool, argv: item.argv }, null, 2), "review-argv"));
  if (item.state === "pending") detail.append(element("p", message(isOwner() ? "reviewExplanation" : "requestPendingHelp"), "fine-print"));
  if (item.result) {
    detail.append(element("h3", message("resultTitle")), element("pre", JSON.stringify(item.result, null, 2)));
    appendArtifacts(detail, item.result.artifacts || []);
  }
  $("review-actions").hidden = item.state !== "pending" || !isOwner();
  $("approve-request").disabled = controlBusy;
  $("reject-request").disabled = controlBusy;
  $("approve-request").textContent = t(controlBusy ? "working" : "approveRequest");
}
async function decideRequest(decision) {
  if (!currentRequest || controlBusy || !isOwner() || currentRequest.state !== "pending") return;
  const current = generation;
  const id = currentRequest.id;
  controlBusy = true;
  controlVersion += 1; controlLoading = false;
  formError("review-error", null); render();
  try {
    const updated = await request(`control/requests/${encodeURIComponent(id)}/decision`, token, { decision });
    if (generation !== current) return;
    currentRequest = updated;
    notice(message("requestChanged"));
  } catch (error) { if (generation === current) formError("review-error", failure(error)); }
  finally {
    if (generation === current) { controlBusy = false; render(); await refreshControl(); }
  }
}
function appendArtifacts(container, artifacts) {
  if (!artifacts.length) return;
  container.append(element("h3", message("filesReady")));
  for (const artifact of artifacts) {
    const row = element("div", undefined, "artifact-row");
    row.append(element("span", `${artifact.name} · ${new Intl.NumberFormat(language).format(artifact.size)} B`));
    const download = element("button", message("download"), "button secondary");
    download.addEventListener("click", () => downloadArtifact(artifact, download));
    row.append(download); container.append(row);
  }
}
async function downloadArtifact(artifact, button) {
  const current = generation;
  const credential = token;
  if (!credential) return;
  let url;
  try {
    url = apiUrl(artifact.download_url || artifact.url);
    if (!url.pathname.startsWith(`${apiBase.pathname}files/`)) throw new Error("Not a file URL");
  } catch { notice(message("invalidDownload"), true); return; }
  button.disabled = true; button.textContent = t("downloading");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120000);
  try {
    const response = await fetch(url, { headers: { Authorization: `Bearer ${credential}` }, credentials: "omit", cache: "no-store", redirect: "error", signal: controller.signal });
    if (!response.ok) throw new Error("Download failed");
    const blob = await response.blob();
    if (generation !== current) return;
    const objectUrl = URL.createObjectURL(blob);
    const link = element("a"); link.href = objectUrl; link.download = artifact.name || "download";
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  } catch { if (generation === current) notice(message("downloadFailed"), true); }
  finally { clearTimeout(timeout); button.disabled = false; button.textContent = t("download"); }
}
$("control-refresh").addEventListener("click", refreshControl);
$("activity-search").addEventListener("input", () => { historyQuery = $("activity-search").value; renderActivity(); });
$("activity-state").addEventListener("change", () => { historyState = $("activity-state").value; renderActivity(); });
$("approve-request").addEventListener("click", () => decideRequest("approve"));
$("reject-request").addEventListener("click", () => decideRequest("reject"));
$("request-dialog").addEventListener("close", () => { currentRequest = null; requestSignature = null; requestGeneration += 1; $("request-detail").replaceChildren(); formError("review-error", null); });
document.addEventListener?.("visibilitychange", () => { if (!document.hidden && controlEnabled()) refreshControl(); });
applyLanguage(language);
