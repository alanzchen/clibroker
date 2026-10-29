/* Same-origin browser client. Credentials, results and activity live only in memory. */
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
  for (const id of ["connect-error", "execute-error"]) {
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
async function request(path, credential, body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120000);
  try {
    const response = await fetch(new URL(path, apiBase), {
      method: body ? "POST" : "GET",
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
  if (executing || connecting) return;
  $("token").value = "";
  formError("connect-error", null);
  $("connect-dialog").showModal();
  $("token").focus();
}
function render() {
  const connected = Boolean(config);
  $("connection-label").textContent = t(connected ? "connected" : "disconnected");
  $("connection-dot").classList.toggle("online", connected);
  $("connect-button").textContent = t(connected ? "switchConnection" : "connectService");
  $("connect-button").disabled = executing || connecting;
  $("refresh-button").disabled = !connected || executing || connecting;
  $("disconnect-button").disabled = !connected || executing || connecting;
  $("copy-mcp").disabled = !connected;
  $("clear-activity").disabled = !activity.length || executing;
  $("connect-submit").disabled = connecting;
  $("connect-submit").textContent = t(connecting ? "connecting" : "connect");
  $("execute-submit").disabled = executing || !selectedRule();
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
    empty.append(button);
    $("tools").append(empty);
  } else {
    if (!config.tools.length) $("tools").append(element("p", message("noTools"), "empty-line"));
    for (const tool of config.tools) {
      const card = element("article", undefined, "tool-card");
      const symbol = element("span", "▤", "tool-symbol");
      symbol.setAttribute("aria-hidden", "true");
      const description = element("div", undefined, "tool-text");
      description.append(element("h3", tool.name), element("p", message("toolCounts", { operations: tool.rules.length, shares: tool.file_shares.length })));
      const button = element("button", message("viewOperations"), "button secondary");
      button.setAttribute("aria-label", t("viewOperationsAria", { tool: tool.name }));
      button.disabled = executing || connecting;
      button.addEventListener("click", () => openTool(tool));
      card.append(symbol, description, button);
      $("tools").append(card);
    }
  }
  renderActivity();
  renderMessages();
  renderResult();
}
function renderActivity() {
  $("activity").replaceChildren();
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
  return message(result.ok ? "completed" : result.timed_out ? "resultTimedOut" : "notCompleted");
}
function renderResult() {
  $("result-section").hidden = !lastResult;
  if (!lastResult) { $("result").textContent = ""; $("result-json").textContent = ""; return; }
  const result = lastResult;
  const stdout = typeof result.stdout === "string" ? result.stdout : JSON.stringify(result.stdout, null, 2);
  $("result-title").textContent = text(resultSummary(result));
  $("result").textContent = [t("exitCode", { code: result.exit_code }), t("duration", {
    milliseconds: new Intl.NumberFormat(language).format(Math.round(result.duration_ms)),
  }), "", t("output"), stdout || t("none"), "", t("errorOutput"), result.stderr || t("none")].join("\n");
  $("result-json").textContent = JSON.stringify(result, null, 2);
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
  if (executing || connecting) return;
  selectedTool = tool;
  $("tool-title").textContent = tool.name;
  $("operation").replaceChildren();
  tool.rules.forEach((rule, index) => $("operation").append(new Option(`${rule.command.join(" ")} (${rule.id})`, String(index))));
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
  if (!executing && !connecting) $(button.dataset.close).close();
});
for (const dialog of document.querySelectorAll("dialog")) dialog.addEventListener("cancel", (event) => {
  if (executing || connecting) event.preventDefault();
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
  if (connecting || executing) return;
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
    $("connect-dialog").close();
    notice(message("connectedNotice"));
  } catch (error) { formError("connect-error", failure(error)); }
  finally { connecting = false; render(); }
});
$("disconnect-button").addEventListener("click", () => {
  if (executing || connecting) return;
  generation += 1;
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
  } catch (error) { if (generation === current) notice(failure(error), true); }
  finally { render(); }
});
$("copy-mcp").addEventListener("click", async () => {
  if (!config) return;
  const current = generation;
  let url;
  try {
    url = new URL(config.mcp_url.replace(/^\//, ""), apiBase);
    if (url.origin !== location.origin) throw new Error("Invalid origin");
  } catch { notice(message("invalidEndpoint"), true); return; }
  try {
    await navigator.clipboard.writeText(url.href);
    if (generation === current) notice(message("copied"));
  } catch { if (generation === current) notice(message("copyManually", { url: url.href })); }
});
$("operation").addEventListener("change", renderParameters);
$("execute-form").addEventListener("input", (event) => {
  if (event.target !== $("confirm-execution")) $("confirm-execution").checked = false;
});
$("execute-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const rule = selectedRule();
  if (!rule || executing || !token) return;
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
  }
});
$("clear-activity").addEventListener("click", () => { activity = []; render(); });
applyLanguage(language);
