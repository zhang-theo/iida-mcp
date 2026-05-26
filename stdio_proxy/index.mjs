#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  PingRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

function defaultIdapyCommand() {
  if (process.env.IIDA_IDAPY) return process.env.IIDA_IDAPY;
  return process.platform === "win32" ? "idapy.cmd" : "idapy";
}

const defaults = {
  backend: process.env.IIDA_BACKEND || "idalib",
  inputFile: process.env.IIDA_INPUT_FILE || "",
  database: process.env.IIDA_DATABASE || "",
  mcpUrl: process.env.IIDA_MCP_URL || "http://127.0.0.1:13897/mcp",
  idapy: defaultIdapyCommand(),
  worker: process.env.IIDA_IDALIB_WORKER || path.join(ROOT, "iida_idalib_worker.py"),
  launcher: process.env.IIDA_LAUNCHER || path.resolve(ROOT, "..", "start-iida-mcp-stdio.ps1"),
  outDir: process.env.IIDA_OUT_DIR || path.join(ROOT, "ida-headless-checks", "codex-auto"),
  readyTimeoutSec: process.env.IIDA_READY_TIMEOUT_SEC || "180",
  keepAliveSec: process.env.IIDA_KEEPALIVE_SEC || "86400",
  fresh: false,
  autoWait: process.env.IIDA_AUTO_WAIT !== "0",
  saveOnExit: process.env.IIDA_SAVE_ON_EXIT !== "0",
};

const managedSessions = [];
let rpcSeq = 1;

function log(message) {
  process.stderr.write(`[iida-mcp-stdio] ${message}\n`);
}

function parseArgs(argv) {
  const opts = { ...defaults };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`missing value for ${arg}`);
      i += 1;
      return argv[i];
    };
    if (arg === "--input" || arg === "--input-file") opts.inputFile = next();
    else if (arg === "--database" || arg === "--idb") opts.database = next();
    else if (arg === "--url" || arg === "--mcp-url") opts.mcpUrl = next();
    else if (arg === "--backend") opts.backend = next();
    else if (arg === "--idapy") opts.idapy = next();
    else if (arg === "--worker") opts.worker = next();
    else if (arg === "--launcher") opts.launcher = next();
    else if (arg === "--out-dir") opts.outDir = next();
    else if (arg === "--ready-timeout-sec") opts.readyTimeoutSec = next();
    else if (arg === "--keepalive-sec") opts.keepAliveSec = next();
    else if (arg === "--fresh") opts.fresh = true;
    else if (arg === "--auto-wait") opts.autoWait = true;
    else if (arg === "--no-auto-wait") opts.autoWait = false;
    else if (arg === "--save-on-exit") opts.saveOnExit = true;
    else if (arg === "--no-save-on-exit") opts.saveOnExit = false;
    else if (arg === "--help" || arg === "-h") {
      process.stdout.write(
        [
          "Usage: node stdio_proxy/index.mjs [--input FILE] [--backend idalib|ida]",
          "",
          "Without --input, the proxy starts immediately and exposes iida_open_file.",
          "Call iida_open_file with the target binary/IDB path at runtime.",
          "By default it uses idapy.cmd/idapy; pass --idapy only to override it.",
          "",
        ].join("\n"),
      );
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

const options = parseArgs(process.argv.slice(2));

function toBool(value, fallback = false) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  return !["", "0", "false", "no", "off"].includes(String(value).trim().toLowerCase());
}

function textResult(data, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    isError,
  };
}

function safeBaseName(value) {
  const base = path.basename(String(value), path.extname(String(value))) || "input";
  return base.replace(/[^A-Za-z0-9_.-]/g, "_");
}

function normalizePathForCompare(value) {
  if (!value) return "";
  return path.resolve(String(value)).toLowerCase();
}

function decodeToolText(result) {
  const item = result?.content?.find(part => part?.type === "text");
  if (!item?.text) return null;
  try {
    return JSON.parse(item.text);
  } catch {
    return item.text;
  }
}

async function readJsonIfExists(file) {
  try {
    return JSON.parse(await fsp.readFile(file, "utf8"));
  } catch {
    return {};
  }
}

async function readTail(file, max = 4000) {
  try {
    const text = await fsp.readFile(file, "utf8");
    return text.slice(-max);
  } catch {
    return "";
  }
}

async function rpc(method, params = undefined, timeoutMs = 120000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const body = { jsonrpc: "2.0", id: rpcSeq++, method };
    if (params !== undefined) body.params = params;
    const resp = await fetch(options.mcpUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
    }
    const data = await resp.json();
    if (data.error) {
      throw new Error(data.error.message || JSON.stringify(data.error));
    }
    return data.result ?? {};
  } finally {
    clearTimeout(timer);
  }
}

async function isReady() {
  try {
    await rpc("ping", undefined, 2000);
    return true;
  } catch {
    return false;
  }
}

async function listRemoteFiles() {
  if (!(await isReady())) return [];
  const result = await rpc("tools/call", { name: "list_files", arguments: {} }, 10000);
  const parsed = decodeToolText(result);
  return Array.isArray(parsed) ? parsed : [];
}

async function getRemoteTools() {
  if (!(await isReady())) return [];
  const result = await rpc("tools/list", undefined, 10000);
  return Array.isArray(result.tools) ? result.tools : [];
}

async function targetRegistered(target) {
  const wanted = normalizePathForCompare(target);
  const files = await listRemoteFiles();
  return files.find(row => normalizePathForCompare(row?.[4]) === wanted) || null;
}

function makeSessionPaths(inputFile) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "");
  const name = `${safeBaseName(inputFile)}-${stamp}-${process.pid}-${Math.random().toString(16).slice(2)}`;
  const dir = path.join(options.outDir, "sessions");
  const outJson = path.join(dir, `${name}.json`);
  return {
    outJson,
    readyFile: `${outJson}.ready`,
    stopFile: `${outJson}.stop`,
    stdoutLog: path.join(dir, `${name}.stdout.log`),
    stderrLog: path.join(dir, `${name}.stderr.log`),
  };
}

function spawnHidden(command, args, opts = {}) {
  const shell = process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
  return spawn(command, args, {
    ...opts,
    shell,
    windowsHide: true,
  });
}

function waitForWorkerReady(child, session, timeoutSec) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const deadline = started + Math.max(1, Number(timeoutSec) || 180) * 1000;
    let exited = false;
    let exitCode = null;

    child.on("exit", code => {
      exited = true;
      exitCode = code;
    });

    const poll = async () => {
      const status = await readJsonIfExists(session.outJson);
      if (fs.existsSync(session.readyFile)) {
        const complete = {
          ...session,
          ...status,
          readyAfterSec: Number(((Date.now() - started) / 1000).toFixed(3)),
        };
        if (status.ok) {
          resolve(complete);
        } else {
          reject(new Error(`iida idalib worker failed: ${JSON.stringify(status.errors || status)}`));
        }
        return;
      }
      if (exited) {
        const stderr = await readTail(session.stderrLog);
        reject(new Error(`iida idalib worker exited with ${exitCode}: ${stderr}`));
        return;
      }
      if (Date.now() > deadline) {
        try {
          await fsp.writeFile(session.stopFile, String(Date.now()), "utf8");
        } catch {
          // best effort
        }
        if (child && !child.killed) {
          child.kill();
        }
        reject(new Error(`iida idalib worker did not become ready within ${timeoutSec}s`));
        return;
      }
      setTimeout(poll, 250);
    };

    poll();
  });
}

async function spawnIdalibWorker(args = {}) {
  const inputFile = args.inputFile || args.path;
  const paths = makeSessionPaths(inputFile);
  await fsp.mkdir(path.dirname(paths.outJson), { recursive: true });
  for (const file of Object.values(paths)) {
    await fsp.rm(file, { force: true }).catch(() => {});
  }

  const readyTimeoutSec = args.readyTimeoutSec ?? options.readyTimeoutSec;
  const keepAliveSec = args.keepAliveSec ?? options.keepAliveSec;
  const workerArgs = [
    options.worker,
    "--input",
    inputFile,
    "--out-dir",
    options.outDir,
    "--out-json",
    paths.outJson,
    "--ready-file",
    paths.readyFile,
    "--stop-file",
    paths.stopFile,
    "--ready-timeout-sec",
    String(readyTimeoutSec),
    "--keepalive-sec",
    String(keepAliveSec),
  ];
  if (args.database) workerArgs.push("--database", args.database);
  if (toBool(args.fresh, options.fresh)) workerArgs.push("--fresh");
  if (toBool(args.autoWait, options.autoWait)) workerArgs.push("--auto-wait");
  if (toBool(args.saveOnExit, options.saveOnExit)) workerArgs.push("--save-on-exit");

  log(`starting idalib worker: ${inputFile}`);
  const child = spawnHidden(options.idapy, workerArgs, { stdio: ["ignore", "pipe", "pipe"] });
  const stdout = fs.createWriteStream(paths.stdoutLog, { flags: "a" });
  const stderr = fs.createWriteStream(paths.stderrLog, { flags: "a" });
  child.stdout.pipe(stdout);
  child.stderr.pipe(stderr);
  child.on("error", error => {
    stderr.write(`${error.stack || error}\n`);
  });

  const session = {
    backend: "idalib",
    inputFile,
    database: args.database || "",
    pid: child.pid,
    child,
    ...paths,
    mcpUrl: options.mcpUrl,
    startedAt: new Date().toISOString(),
  };
  managedSessions.push(session);
  child.on("exit", () => forgetSession(session));
  try {
    const readySession = await waitForWorkerReady(child, session, readyTimeoutSec);
    Object.assign(session, readySession, { child });
    return session;
  } catch (error) {
    forgetSession(session);
    if (child && !child.killed) {
      child.kill();
    }
    throw error;
  }
}

function runIdaLauncher(args = {}) {
  return new Promise(async (resolve, reject) => {
    const inputFile = args.inputFile || args.path;
    const paths = makeSessionPaths(inputFile);
    await fsp.mkdir(path.dirname(paths.outJson), { recursive: true });

    const readyTimeoutSec = args.readyTimeoutSec ?? options.readyTimeoutSec;
    const keepAliveSec = args.keepAliveSec ?? options.keepAliveSec;
    const psArgs = [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      options.launcher,
      "-McpUrl",
      options.mcpUrl,
      "-OutDir",
      options.outDir,
      "-ReadyTimeoutSec",
      String(readyTimeoutSec),
      "-KeepAliveSeconds",
      String(keepAliveSec),
      "-SessionJson",
      paths.outJson,
      "-NoProxy",
    ];
    if (inputFile) psArgs.push("-InputFile", inputFile);
    if (args.database) psArgs.push("-Database", args.database);
    if (toBool(args.fresh, options.fresh)) psArgs.push("-Fresh");
    if (toBool(args.autoWait, options.autoWait)) psArgs.push("-AutoWait");

    log(`starting ida.exe launcher: ${inputFile}`);
    const child = spawnHidden("powershell.exe", psArgs, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", chunk => {
      const text = chunk.toString();
      stderr += text;
      process.stderr.write(text);
    });
    child.on("error", reject);
    child.on("exit", async code => {
      const status = await readJsonIfExists(paths.outJson);
      const session = {
        backend: "ida",
        ...paths,
        ...status,
        inputFile,
        database: args.database || status.database || "",
        mcpUrl: options.mcpUrl,
        startedAt: new Date().toISOString(),
      };
      if (code === 0) {
        managedSessions.push(session);
        resolve(session);
      } else {
        reject(new Error(`ida launcher exited with ${code}: ${stderr.slice(-2000)}`));
      }
    });
  });
}

async function startTargetSession(args = {}) {
  const backend = String(args.backend || options.backend || "idalib").toLowerCase();
  if (backend === "ida" || backend === "ida-exe") {
    return runIdaLauncher(args);
  }
  if (backend !== "auto") {
    return spawnIdalibWorker(args);
  }
  try {
    return await spawnIdalibWorker(args);
  } catch (error) {
    log(`idalib backend failed, trying ida.exe launcher: ${error.message}`);
    return runIdaLauncher(args);
  }
}

function serializeSession(session) {
  const { child, ...rest } = session;
  return rest;
}

function forgetSession(session) {
  const idx = managedSessions.indexOf(session);
  if (idx >= 0) managedSessions.splice(idx, 1);
}

async function openFile(args = {}) {
  const target = args.path || args.input_path || args.inputFile;
  if (!target) {
    return textResult({ ok: false, error: "missing path; pass target binary/IDB in iida_open_file.path" }, true);
  }
  if (!fs.existsSync(target)) {
    return textResult({ ok: false, error: `file not found: ${target}` }, true);
  }

  const already = await targetRegistered(target).catch(() => null);
  if (already) {
    return textResult({
      ok: true,
      alreadyRegistered: true,
      path: path.resolve(target),
      mcpUrl: options.mcpUrl,
      file: already,
      files: await listRemoteFiles(),
    });
  }

  const session = await startTargetSession({
    inputFile: target,
    database: args.database || args.idb || "",
    backend: args.backend,
    readyTimeoutSec: args.ready_timeout_sec ?? args.timeout ?? options.readyTimeoutSec,
    keepAliveSec: args.keepalive_sec ?? options.keepAliveSec,
    fresh: args.fresh,
    autoWait: args.auto_wait ?? args.autoWait,
    saveOnExit: args.save_on_exit ?? args.saveOnExit,
  });

  const files = await listRemoteFiles();
  const registered =
    files.find(row => normalizePathForCompare(row?.[4]) === normalizePathForCompare(target)) ||
    files.find(row => normalizePathForCompare(row?.[4]) === normalizePathForCompare(session.file?.path)) ||
    null;

  return textResult({
    ok: true,
    path: path.resolve(target),
    mcpUrl: options.mcpUrl,
    registered: Boolean(registered),
    file: registered,
    files,
    session: serializeSession(session),
  });
}

async function status() {
  const ready = await isReady();
  let files = [];
  let tools = 0;
  if (ready) {
    files = await listRemoteFiles();
    tools = (await getRemoteTools()).length;
  }
  return textResult({
    ok: true,
    ready,
    mcpUrl: options.mcpUrl,
    files,
    tools,
    managedSessions: managedSessions.map(serializeSession),
  });
}

async function closeFile(args = {}) {
  const targetPath = args.path ? normalizePathForCompare(args.path) : "";
  const targetPid = args.pid ? Number(args.pid) : 0;
  const closeAll = toBool(args.all, false);
  const force = toBool(args.force, false);
  const matches = managedSessions.filter(session => {
    if (closeAll) return true;
    if (targetPid && Number(session.pid) === targetPid) return true;
    if (targetPath && normalizePathForCompare(session.inputFile) === targetPath) return true;
    return !targetPath && !targetPid && session === managedSessions[managedSessions.length - 1];
  });

  if (!matches.length) {
    return textResult({ ok: false, error: "no matching managed iida IDA session" }, true);
  }

  const closed = [];
  for (const session of matches) {
    if (session.stopFile) {
      await fsp.writeFile(session.stopFile, String(Date.now()), "utf8");
    }
    if (force && session.child && !session.child.killed) {
      session.child.kill();
    }
    if (!session.child) {
      forgetSession(session);
    }
    closed.push({
      backend: session.backend,
      pid: session.pid,
      inputFile: session.inputFile,
      stopFile: session.stopFile || "",
      graceful: Boolean(session.stopFile),
      forced: force,
    });
  }
  return textResult({ ok: true, closed });
}

const MANAGEMENT_TOOLS = [
  {
    name: "iida_open_file",
    description: "Open a binary/IDB in a background IDA Pro idalib session and attach it to iida-mcp.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Target binary or IDB path" },
        database: { type: "string", description: "Optional IDB path to reuse/create", optional: true },
        backend: { type: "string", description: "idalib, ida, or auto; default idalib", optional: true },
        fresh: { type: "boolean", description: "Delete the target IDB before opening", optional: true },
        auto_wait: { type: "boolean", description: "Wait for IDA auto-analysis before starting iida-mcp; default true", optional: true },
        save_on_exit: { type: "boolean", description: "Save the IDB when the managed session closes; default true", optional: true },
        ready_timeout_sec: { type: "integer", description: "Seconds to wait for readiness; default 180", optional: true },
        keepalive_sec: { type: "integer", description: "Seconds to keep the session alive; default 86400", optional: true },
      },
      required: ["path"],
    },
  },
  {
    name: "iida_status",
    description: "Report iida-mcp readiness, registered files, remote tool count, and managed IDA sessions.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "iida_close_file",
    description: "Stop a managed IDA session by path, pid, or the latest managed session by default.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Target path opened by iida_open_file", optional: true },
        pid: { type: "integer", description: "Managed worker process id", optional: true },
        all: { type: "boolean", description: "Close all managed sessions", optional: true },
        force: { type: "boolean", description: "Kill the child process after writing the stop file", optional: true },
      },
    },
  },
];

const MANAGEMENT_NAMES = new Set(MANAGEMENT_TOOLS.map(tool => tool.name));

async function handleManagementTool(name, args) {
  try {
    if (name === "iida_open_file") return await openFile(args);
    if (name === "iida_status") return await status(args);
    if (name === "iida_close_file") return await closeFile(args);
    return textResult({ ok: false, error: `unknown management tool: ${name}` }, true);
  } catch (error) {
    return textResult({
      ok: false,
      tool: name,
      error: error.message || String(error),
      stack: error.stack || "",
    }, true);
  }
}

async function maybeOpenStartupInput() {
  if (!options.inputFile && !options.database) {
    if (await isReady()) {
      log(`iida-mcp already ready at ${options.mcpUrl}`);
    } else {
      log("no startup input configured; waiting for iida_open_file");
    }
    return;
  }
  await startTargetSession({
    inputFile: options.inputFile || options.database,
    database: options.database,
    readyTimeoutSec: options.readyTimeoutSec,
    keepAliveSec: options.keepAliveSec,
    fresh: options.fresh,
    autoWait: options.autoWait,
    saveOnExit: options.saveOnExit,
  });
}

async function main() {
  await maybeOpenStartupInput();

  const server = new Server(
    { name: "iida-mcp-stdio-proxy", version: "0.1.0" },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
      instructions:
        "Stdio entrypoint for iida-mcp. Call iida_open_file with a target path to start IDA Pro idalib, then use the normal iida-mcp tools.",
    },
  );

  server.setRequestHandler(PingRequestSchema, async () => ({}));

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const remoteTools = await getRemoteTools().catch(error => {
      log(`tools/list remote unavailable: ${error.message}`);
      return [];
    });
    const filtered = remoteTools.filter(tool => !MANAGEMENT_NAMES.has(tool.name));
    return { tools: [...MANAGEMENT_TOOLS, ...filtered] };
  });

  server.setRequestHandler(CallToolRequestSchema, async request => {
    const name = request.params.name;
    const args = request.params.arguments || {};
    if (MANAGEMENT_NAMES.has(name)) {
      return handleManagementTool(name, args);
    }
    if (!(await isReady())) {
      return textResult(
        {
          ok: false,
          error: "iida-mcp is not ready; call iida_open_file with a target binary/IDB path first",
          mcpUrl: options.mcpUrl,
        },
        true,
      );
    }
    try {
      return await rpc("tools/call", request.params, 180000);
    } catch (error) {
      return textResult({
        ok: false,
        tool: name,
        error: error.message || String(error),
      }, true);
    }
  });

  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    const local = [{
      uri: "iida-stdio://status",
      name: "iida stdio proxy status",
      description: "Proxy readiness, registered files, and managed sessions.",
      mimeType: "application/json",
    }];
    if (!(await isReady())) return { resources: local };
    const remote = await rpc("resources/list").catch(() => ({ resources: [] }));
    return { resources: [...local, ...(remote.resources || [])] };
  });

  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
    if (!(await isReady())) return { resourceTemplates: [] };
    return rpc("resources/templates/list").catch(() => ({ resourceTemplates: [] }));
  });

  server.setRequestHandler(ReadResourceRequestSchema, async request => {
    if (request.params.uri === "iida-stdio://status") {
      const ready = await isReady();
      const files = ready ? await listRemoteFiles() : [];
      return {
        contents: [{
          uri: request.params.uri,
          mimeType: "application/json",
          text: JSON.stringify(
            { ready, mcpUrl: options.mcpUrl, files, managedSessions: managedSessions.map(serializeSession) },
            null,
            2,
          ),
        }],
      };
    }
    if (!(await isReady())) {
      throw new Error("iida-mcp is not ready; call iida_open_file first");
    }
    return rpc("resources/read", request.params);
  });

  server.setRequestHandler(ListPromptsRequestSchema, async () => {
    if (!(await isReady())) return { prompts: [] };
    return rpc("prompts/list").catch(() => ({ prompts: [] }));
  });

  server.setRequestHandler(GetPromptRequestSchema, async () => ({ messages: [] }));

  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("stdio proxy ready");
}

async function stopManagedSessions(force = false) {
  for (const session of managedSessions) {
    if (session.stopFile) {
      await fsp.writeFile(session.stopFile, String(Date.now()), "utf8").catch(() => {});
    }
    if (force && session.child && !session.child.killed) {
      session.child.kill();
    }
  }
}

process.on("exit", () => {
  for (const session of managedSessions) {
    if (session.child && !session.child.killed) {
      session.child.kill();
    }
  }
});

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, async () => {
    await stopManagedSessions(true).catch(() => {});
    process.exit(0);
  });
}

main().catch(error => {
  process.stderr.write(`[iida-mcp-stdio] fatal: ${error.stack || error}\n`);
  process.exit(1);
});
