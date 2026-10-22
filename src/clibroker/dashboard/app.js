/* Same-origin browser client. Secrets and activity deliberately live only in memory. */
"use strict";
const $ = (id) => document.getElementById(id);
// Resolve from the asset, including /dashboard/index.html and proxy prefixes.
const apiBase = new URL("../../", document.currentScript.src);
let token = "";
let config = null;
let selectedTool = null;
let activity = [];
let generation = 0;
let executing = false;
let connecting = false;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").className = error ? "notice error" : "notice";
  $("notice").hidden = !message;
}
function formError(id, message) {
  $(id).textContent = message;
  $(id).hidden = !message;
}
async function request(path, credential, body) {
  // Never follow a redirect with the credential or execute a server-provided URL.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120000);
  try {
    const response = await fetch(new URL(path, apiBase), {
      method: body ? "POST" : "GET",
      headers: {
        Authorization: `Bearer ${credential}`,
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    if (response.status === 401) throw new Error("访问凭证无效或已失效，请重新连接。");
    if (response.status === 403) throw new Error("当前凭证没有执行此操作的权限。");
    if (!response.ok) throw new Error(`服务返回错误（${response.status}），请联系管理员。`);
    return await response.json();
  } catch (error) {
    if (error.name === "AbortError") throw new Error("等待结果超时，操作可能仍在服务端执行。请先确认状态，不要直接重复提交。");
    if (error instanceof TypeError) throw new Error("无法连接服务，请检查网络和服务状态。若已提交操作，请先确认是否完成。");
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
function openConnection() {
  if (executing || connecting) return;
  $("token").value = "";
  formError("connect-error", "");
  $("connect-dialog").showModal();
  $("token").focus();
}
function render() {
  const connected = Boolean(config);
  $("connection-label").textContent = connected ? "已连接服务" : "尚未连接";
  $("connection-dot").classList.toggle("online", connected);
  $("connect-button").textContent = connected ? "切换连接" : "连接服务";
  $("connect-button").disabled = executing || connecting;
  $("refresh-button").disabled = !connected || executing || connecting;
  $("disconnect-button").disabled = !connected || executing || connecting;
  $("copy-mcp").disabled = !connected;
  $("clear-activity").disabled = !activity.length || executing;
  $("client-name").textContent = connected ? config.client_name : "等待连接";
  $("client-summary").textContent = connected ? `当前凭证可使用 ${config.tools.length} 个工具，权限由服务端管理。` : "连接后查看可用工具与操作。";
  if (!connected) {
    $("tools-subtitle").textContent = "连接后，工具会自动显示在这里。";
    $("tools").replaceChildren();
    const empty = element("div", undefined, "empty");
    empty.append(element("span", "▤", "empty-icon"), element("h3", "先连接你的 clibroker"), element("p", "无需逐个添加工具。使用已有访问凭证，查看为你配置的功能。"));
    const button = element("button", "连接服务 →", "button primary");
    button.addEventListener("click", openConnection);
    empty.append(button);
    $("tools").append(empty);
  } else {
    $("tools-subtitle").textContent = "只显示当前凭证可见的工具。账号是否在线需实际调用确认。";
    $("tools").replaceChildren();
    if (!config.tools.length) $("tools").append(element("p", "当前凭证没有可用工具，请联系服务管理员分配权限。", "empty-line"));
    for (const tool of config.tools) {
      const card = element("article", undefined, "tool-card");
      const symbol = element("span", "▤", "tool-symbol");
      symbol.setAttribute("aria-hidden", "true");
      const text = element("div", undefined, "tool-text");
      text.append(element("h3", tool.name), element("p", `${tool.rules.length} 项可用操作 · ${tool.file_shares.length} 个共享目录`));
      const button = element("button", "查看操作", "button secondary");
      button.setAttribute("aria-label", `查看 ${tool.name} 的操作与权限`);
      button.disabled = executing;
      button.addEventListener("click", () => openTool(tool));
      card.append(symbol, text, button);
      $("tools").append(card);
    }
  }
  renderActivity();
}
function renderActivity() {
  $("activity").replaceChildren();
  if (!activity.length) $("activity").append(element("p", "还没有操作记录。选择一个工具，查看可用操作。", "empty-line"));
  for (const item of activity) {
    const row = element("div", undefined, "activity-row");
    const icon = element("span", item.ok ? "✓" : "!", item.ok ? "activity-icon" : "activity-icon failed");
    icon.setAttribute("aria-hidden", "true");
    const text = element("div");
    text.append(element("h3", `${item.tool} · ${item.command}`), element("p", item.summary));
    const time = element("time", item.date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" }));
    time.dateTime = item.date.toISOString();
    row.append(icon, text, time);
    $("activity").append(row);
  }
}
function selectedRule() {
  return selectedTool?.rules[Number($("operation").value)];
}
function addInput(label, id, { enumValues, help, checkbox = false } = {}) {
  const wrapper = element("div");
  const field = element(enumValues ? "select" : "input");
  field.id = id;
  if (enumValues) {
    field.append(new Option("请选择", ""));
    for (const value of enumValues) field.append(new Option(value, value));
  } else field.type = checkbox ? "checkbox" : "text";
  field.autocomplete = "off";
  const caption = element("label", checkbox ? undefined : label, checkbox ? "check-row" : undefined);
  caption.htmlFor = id;
  if (checkbox) { caption.append(field, document.createTextNode(label)); wrapper.append(caption); }
  else wrapper.append(caption, field);
  if (help) {
    const hint = element("p", help, "field-help");
    hint.id = `${id}-help`;
    field.setAttribute("aria-describedby", hint.id);
    wrapper.append(hint);
  }
  $("parameters").append(wrapper);
  return field;
}
function renderParameters() {
  $("parameters").replaceChildren();
  $("confirm-execution").checked = false;
  $("extra-args").value = "";
  $("extra-details").open = false;
  $("result-section").hidden = true;
  $("result").textContent = "";
  $("result-json").textContent = "";
  formError("execute-error", "");
  const rule = selectedRule();
  $("execute-submit").disabled = !rule || executing;
  if (!rule) {
    $("parameters").append(element("p", "当前工具只开放共享目录，没有可执行操作。", "field-help"));
    return;
  }
  rule.command.forEach((part, index) => {
    if (part === "*") {
      addInput(`命令第 ${index + 1} 段`, `command-${index}`, {
        help: "这里允许选择一个子命令。每个输入框只填写一段命令，不要填写整行命令。",
      }).required = true;
    }
  });
  if (selectedTool.argv_normalization?.patterns.length) {
    addInput("全局参数（JSON 字符串数组）", "global-args", {
      help: '可选，例如 ["account=personal"]。只接受服务端配置允许的参数，会放在命令前面。',
    });
  }
  $("extra-args-label").textContent = rule.allow_any_args ? "操作参数（JSON 字符串数组）" : "额外参数（JSON 字符串数组）";
  $("extra-details").open = rule.allow_any_args;
  $("extra-summary").textContent = rule.allow_any_args ? "填写操作参数" : "更多参数";
  rule.positionals.forEach((pos, index) => addInput(
    pos.variadic ? `${pos.name}（多个值）` : pos.name, `pos-${index}`, {
      enumValues: pos.variadic ? null : pos.enum,
      help: [pos.variadic ? '必填，至少一项。填写 JSON 字符串数组，例如 ["第一项", "第二项"]。' : "必填，具体要求由服务端检查。", pos.pattern ? `格式要求：${pos.pattern}` : "", pos.variadic && pos.enum ? `可选值：${pos.enum.join("、")}` : ""].filter(Boolean).join("\n"),
    },
  ).required = true);
  rule.flags.forEach((flag, index) => addInput(flag, `flag-${index}`, { help: "可选；留空则不传递。" }));
  rule.standalone_flags.forEach((flag, index) => addInput(flag, `switch-${index}`, { checkbox: true }));
}
function openTool(tool) {
  selectedTool = tool;
  $("tool-title").textContent = tool.name;
  $("operation").replaceChildren();
  tool.rules.forEach((rule, index) => $("operation").append(new Option(`${rule.command.join(" ")}（${rule.id}）`, String(index))));
  $("operation").disabled = !tool.rules.length;
  renderParameters();
  $("tool-dialog").showModal();
}
function stringArray(value, label) {
  let parsed;
  try { parsed = JSON.parse(value); } catch { throw new Error(`${label}需要填写有效的 JSON 数组。`); }
  if (!Array.isArray(parsed) || parsed.some((part) => typeof part !== "string")) throw new Error(`${label}必须是字符串数组。`);
  return parsed;
}
function buildArgv(rule) {
  const globalArgs = $("global-args")?.value.trim();
  const argv = globalArgs ? stringArray(globalArgs, "全局参数") : [];
  argv.push(...rule.command.map((part, index) => {
    if (part !== "*") return part;
    const value = $(`command-${index}`).value.trim();
    if (!value) throw new Error("请填写通配命令的每一段。");
    return value;
  }));
  rule.flags.forEach((flag, index) => {
    const value = $(`flag-${index}`).value;
    if (value !== "") argv.push(flag, value);
  });
  rule.standalone_flags.forEach((flag, index) => { if ($(`switch-${index}`).checked) argv.push(flag); });
  let omitted = false;
  rule.positionals.forEach((pos, index) => {
    const value = $(`pos-${index}`).value;
    const values = pos.variadic ? stringArray(value.trim() || "[]", pos.name) : (value === "" ? [] : [value]);
    if (pos.variadic && !values.length) throw new Error(`${pos.name}至少需要填写一项。`);
    if (!values.length) omitted = true;
    else if (omitted) throw new Error("请按顺序填写参数，不能跳过前面的参数填写后面的参数。");
    else argv.push(...values);
  });
  if ($("extra-args").value.trim()) argv.push(...stringArray($("extra-args").value, "额外参数"));
  return argv;
}

$("connect-button").addEventListener("click", openConnection);
$("empty-connect").addEventListener("click", openConnection);
for (const button of document.querySelectorAll("[data-close]")) button.addEventListener("click", () => {
  if (executing || connecting) return;
  $(button.dataset.close).close();
});
for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("cancel", (event) => { if (executing || connecting) event.preventDefault(); });
}
$("connect-dialog").addEventListener("close", () => { $("token").value = ""; });
$("tool-dialog").addEventListener("close", () => {
  selectedTool = null;
  $("parameters").replaceChildren();
  $("extra-args").value = "";
  $("result").textContent = "";
  $("result-json").textContent = "";
});
$("connect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (connecting || executing) return;
  const credential = $("token").value.trim();
  if (!credential) return;
  connecting = true;
  $("connect-submit").disabled = true;
  $("connect-submit").textContent = "连接中…";
  formError("connect-error", "");
  try {
    const next = await request("client-config", credential);
    token = credential;
    config = next;
    generation += 1;
    activity = [];
    $("connect-dialog").close();
    notice("已连接。下方展示的是当前凭证实际可用的工具。");
  } catch (error) { formError("connect-error", error.message); }
  finally {
    connecting = false;
    $("connect-submit").disabled = false;
    $("connect-submit").textContent = "连接";
    render();
  }
});
$("disconnect-button").addEventListener("click", () => {
  if (executing || connecting) return;
  generation += 1;
  token = "";
  config = null;
  selectedTool = null;
  activity = [];
  $("result").textContent = "";
  $("result-json").textContent = "";
  $("parameters").replaceChildren();
  $("token").value = "";
  notice("已断开连接，并清除了本页保存的凭证与操作记录。");
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
    notice("工具与权限已刷新。");
  } catch (error) { if (generation === current) notice(error.message, true); }
  finally { render(); }
});
$("copy-mcp").addEventListener("click", async () => {
  if (!config) return;
  const current = generation;
  let url;
  try {
    url = new URL(config.mcp_url.replace(/^\//, ""), apiBase);
    if (url.origin !== location.origin) throw new Error("Invalid origin");
  } catch {
    notice("服务返回了无效的接入地址。", true);
    return;
  }
  try {
    await navigator.clipboard.writeText(url.href);
    if (generation === current) notice("MCP 地址已复制。请只交给可信助手。");
  } catch {
    if (generation === current) notice(`无法自动复制，请手动复制 MCP 地址：${url.href}`);
  }
});
$("operation").addEventListener("change", renderParameters);
$("execute-form").addEventListener("input", (event) => {
  if (event.target !== $("confirm-execution")) $("confirm-execution").checked = false;
});
$("execute-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const rule = selectedRule();
  if (!rule || executing || !token || !$("confirm-execution").checked) return;
  formError("execute-error", "");
  let argv;
  try { argv = buildArgv(rule); } catch (error) { formError("execute-error", error.message); return; }
  const tool = selectedTool.name;
  const item = { tool, command: rule.command.join(" "), date: new Date(), ok: false };
  executing = true;
  $("execute-submit").disabled = true;
  $("execute-submit").textContent = "执行中…";
  for (const field of $("execute-form").querySelectorAll("input, select, textarea, button")) field.disabled = true;
  document.querySelector('[data-close="tool-dialog"]').disabled = true;
  $("result-section").hidden = true;
  render();
  try {
    const result = await request("execute", token, { tool, argv });
    item.ok = result.ok;
    item.summary = result.ok ? "已完成" : result.timed_out ? "执行超时，请先确认实际结果" : "未完成，请查看返回结果";
    $("result-title").textContent = item.summary;
    const stdout = typeof result.stdout === "string" ? result.stdout : JSON.stringify(result.stdout, null, 2);
    $("result").textContent = `退出码：${result.exit_code}\n用时：${Math.round(result.duration_ms)} 毫秒\n\n返回内容：\n${stdout || "（无）"}\n\n错误信息：\n${result.stderr || "（无）"}`;
    $("result-json").textContent = JSON.stringify(result, null, 2);
    $("result-section").hidden = false;
  } catch (error) {
    item.summary = error.message;
    formError("execute-error", error.message);
  } finally {
    activity.unshift(item);
    activity = activity.slice(0, 30);
    executing = false;
    $("execute-submit").disabled = false;
    $("execute-submit").textContent = "确认并执行";
    for (const field of $("execute-form").querySelectorAll("input, select, textarea, button")) field.disabled = false;
    document.querySelector('[data-close="tool-dialog"]').disabled = false;
    $("confirm-execution").checked = false;
    render();
  }
});
$("clear-activity").addEventListener("click", () => { activity = []; render(); });
