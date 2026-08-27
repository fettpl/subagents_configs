import { spawn } from "node:child_process";
import { lstat } from "node:fs/promises";
import * as path from "node:path";
import { Type } from "@sinclair/typebox";

const MAX_OUTPUT_BYTES = 8192;
const VALIDATION_TIMEOUT_MS = 900_000;
const OUTPUT_TRUNCATION_MARKER = "\n[output truncated]";
const HELPER_RELATIVE_PATH = ".subagents_configs/validation/run-validation-isolated.py";
const SAFE_PATH_CHARS = /[\u0000-\u001f\u007f\u2028\u2029]/;

type ValidationResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

function safeAbsolute(value: unknown, label: string): string {
  if (typeof value !== "string" || !value || !path.isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path`);
  }
  if (SAFE_PATH_CHARS.test(value) || value.includes("\\") || value.includes('"')) {
    throw new Error(`${label} contains unsafe characters`);
  }
  if (
    value === path.parse(value).root ||
    value !== path.normalize(value) ||
    value.split(path.sep).includes("..")
  ) {
    throw new Error(`${label} must be canonical`);
  }
  return value;
}

function contained(base: string, candidate: string): boolean {
  const relative = path.relative(base, candidate);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

async function verifiedPaths(): Promise<{ agentDir: string; helperPath: string }> {
  const agentDir = safeAbsolute(process.env.PI_CODING_AGENT_DIR, "PI_CODING_AGENT_DIR");
  const helperPath = path.join(agentDir, HELPER_RELATIVE_PATH);
  if (!contained(agentDir, helperPath)) {
    throw new Error("validation helper is outside PI_CODING_AGENT_DIR");
  }

  // Check every existing path component, including ancestors above the
  // configured directory. A symlink at any level could redirect the helper
  // lookup outside the lexical directory boundary.
  const root = path.parse(agentDir).root;
  const relativeAgentDir = path.relative(root, agentDir);
  let current = root;
  for (const component of relativeAgentDir.split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const item = await lstat(current);
    if (item.isSymbolicLink()) {
      throw new Error("PI_CODING_AGENT_DIR ancestors must not contain symlinks");
    }
    if (!item.isDirectory()) {
      throw new Error("PI_CODING_AGENT_DIR must be a regular directory");
    }
  }

  // Walk every component below the validated agent directory with lstat. This
  // keeps a symlinked validation directory from escaping the lexical boundary
  // checked above, and ensures the helper itself is a regular file.
  const relative = path.relative(agentDir, helperPath);
  let current = agentDir;
  const components = relative.split(path.sep).filter(Boolean);
  for (const [index, component] of components.entries()) {
    current = path.join(current, component);
    const item = await lstat(current);
    if (item.isSymbolicLink()) {
      throw new Error("validation helper path must not contain symlinks");
    }
    const isHelper = index === components.length - 1;
    if ((isHelper && !item.isFile()) || (!isHelper && !item.isDirectory())) {
      throw new Error(isHelper ? "validation helper must be a regular file" : "validation helper parent must be a directory");
    }
  }
  return { agentDir, helperPath };
}

function checkedArguments(value: unknown): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) {
    throw new Error("argv must contain between 1 and 64 arguments");
  }
  if (value.some((item) => typeof item !== "string" || !item || SAFE_PATH_CHARS.test(item))) {
    throw new Error("argv contains an empty or unsafe argument");
  }
  return value;
}

function redact(value: string, agentDir: string): string {
  const escapedAgentDir = agentDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return value
    .replace(new RegExp(escapedAgentDir, "g"), "<PI_AGENT_DIR>")
    .replace(/(?:^|[\s('"=])\/(?:[^\s'"`\/]+\/)*[^\s'"`\/]+/g, "$1<PATH>")
    .replace(/\b((?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|AUTH)[A-Z0-9_-]*)\s*[=:]\s*[^\s]+/gi, "$1=<REDACTED>")
    .replace(/\b([A-Z][A-Z0-9_]{2,})\s*=\s*[^\s]+/g, "$1=<REDACTED>")
    .replace(/\bBearer\s+[^\s]+/gi, "Bearer <REDACTED>");
}

function boundedOutput(value: string, truncated: boolean): string {
  const marker = truncated ? OUTPUT_TRUNCATION_MARKER : "";
  const available = MAX_OUTPUT_BYTES - Buffer.byteLength(marker, "utf8");
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength <= available) {
    return `${value}${marker}`;
  }
  return `${bytes.subarray(0, Math.max(0, available)).toString("utf8")}${OUTPUT_TRUNCATION_MARKER}`;
}

function textResult(text: string, isError = false): ValidationResult {
  return { content: [{ type: "text", text }], ...(isError ? { isError: true } : {}) };
}

async function executeValidation(input: unknown): Promise<ValidationResult> {
  let argv: string[];
  let paths: { agentDir: string; helperPath: string };
  try {
    argv = checkedArguments((input as { argv?: unknown })?.argv);
    paths = await verifiedPaths();
  } catch (error) {
    return textResult(`validation rejected: ${error instanceof Error ? error.message : "invalid input"}`, true);
  }

  const agentDir = paths.agentDir;
  const helperPath = paths.helperPath;
  const params = { argv };
  const args = [helperPath, "--", ...params.argv];
  return await new Promise((resolve) => {
    const child = spawn("python3", args, {
      cwd: process.cwd(),
      env: { PATH: "/usr/bin:/bin", PI_CODING_AGENT_DIR: agentDir },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let outputBytes = 0;
    let truncated = false;
    let timedOut = false;
    const collect = (chunk: Buffer): void => {
      if (outputBytes >= MAX_OUTPUT_BYTES) {
        truncated = true;
        child.kill("SIGTERM");
        return;
      }
      const remaining = MAX_OUTPUT_BYTES - outputBytes;
      const bounded = chunk.subarray(0, remaining);
      chunks.push(bounded);
      outputBytes += bounded.byteLength;
      if (bounded.byteLength < chunk.byteLength) {
        truncated = true;
        child.kill("SIGTERM");
      }
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, VALIDATION_TIMEOUT_MS);
    child.once("error", (error) => {
      clearTimeout(timeout);
      resolve(textResult(`validation failed: ${redact(error.message, paths.agentDir)}`, true));
    });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      const output = boundedOutput(
        redact(Buffer.concat(chunks).toString("utf8"), paths.agentDir),
        truncated,
      );
      const status = timedOut ? "timeout" : code === null ? `signal:${signal ?? "unknown"}` : `exit:${code}`;
      resolve(textResult(`${status}\n${output}`, code !== 0 || timedOut));
    });
  });
}

export default function registerRunValidation(pi: { registerTool: (tool: unknown) => void }): void {
  pi.registerTool({
    name: "run_validation",
    label: "Run validation",
    description: "Run one bounded validation command through the isolated backend.",
    parameters: Type.Object({
      argv: Type.Array(Type.String(), { minItems: 1, maxItems: 64 }),
    }),
    execute: async (_toolCallId: string, params: unknown): Promise<ValidationResult> => executeValidation(params),
  });
}
