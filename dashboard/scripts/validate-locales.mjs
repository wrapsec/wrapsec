// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Pre-build locale catalog guard (runs as `prebuild`, before `next build`).
 *
 * This validates the GENERATED frontend catalog the dashboard actually ships
 * (dashboard/messages/*). It is a dependency-light STRUCTURAL/presence check --
 * the canonical freshness (matches locales/) is enforced by the Python generator
 * guard in CI, and executable ICU syntax is validated by next-intl at build time
 * (the layered ICU model). It intentionally does NOT regenerate (no Python in the
 * dashboard image).
 */
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const MESSAGES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "messages");
const REQUIRED_NAMESPACES = ["common", "errors", "forms", "notifications", "pages"];

function fail(msg) {
  console.error(`locale catalog invalid: ${msg}`);
  process.exit(1);
}

function readJson(path) {
  if (!existsSync(path)) fail(`missing ${path}`);
  try {
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch (e) {
    fail(`${path} is not valid JSON: ${e.message}`);
  }
}

// ICU curly-brace delimiters must balance (structural only; next-intl compiles
// the executable syntax at build time).
function checkIcuBalance(prefix, node) {
  if (typeof node === "string") {
    let depth = 0;
    for (const ch of node) {
      if (ch === "{") depth++;
      else if (ch === "}" && --depth < 0) fail(`unbalanced '}' in ${prefix}`);
    }
    if (depth !== 0) fail(`unbalanced '{' in ${prefix}`);
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) checkIcuBalance(`${prefix}.${k}`, v);
  }
}

const config = readJson(join(MESSAGES_DIR, "locale-config.json"));
const supported = config.supported_locales;
if (!Array.isArray(supported) || supported.length === 0) fail("supported_locales empty");
if (!config.catalog_version) fail("catalog_version missing");
if (!supported.includes(config.default_locale)) fail("default_locale not in supported_locales");

for (const locale of supported) {
  const messages = readJson(join(MESSAGES_DIR, `${locale}.json`));
  for (const ns of REQUIRED_NAMESPACES) {
    if (!(ns in messages)) fail(`locale '${locale}' missing namespace '${ns}'`);
  }
  checkIcuBalance(locale, messages);
}

console.log(
  `locale catalog OK (v${config.catalog_version}, locales: ${supported.join(", ")})`
);
