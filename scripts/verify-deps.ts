import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface DepVerifyResult {
  ok: boolean;
  errors: string[];
  mcpUseVersion?: string;
}

const EXACT_SEMVER_REGEX = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function verifyDependencies(rootDir: string): DepVerifyResult {
  const errors: string[] = [];
  const pkgPath = path.join(rootDir, "package.json");
  const lockPath = path.join(rootDir, "pnpm-lock.yaml");

  if (!fs.existsSync(pkgPath)) {
    return { ok: false, errors: ["package.json does not exist."] };
  }
  if (!fs.existsSync(lockPath)) {
    return { ok: false, errors: ["pnpm-lock.yaml does not exist."] };
  }

  const pkgJson = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  const allDeps = {
    ...(pkgJson.dependencies ?? {}),
    ...(pkgJson.devDependencies ?? {}),
  };

  for (const [name, versionSpec] of Object.entries(allDeps)) {
    if (!EXACT_SEMVER_REGEX.test(versionSpec)) {
      errors.push(
        `Dependency '${name}' uses non-pinned version specifier '${versionSpec}'. Exact semver is required.`
      );
    }
  }

  const lockContent = fs.readFileSync(lockPath, "utf8");
  const expectedMcpUse = pkgJson.dependencies?.["mcp-use"];
  if (!expectedMcpUse) {
    errors.push("package.json is missing required dependency 'mcp-use'.");
  } else {
    const specifierBlockMatch = lockContent.match(
      new RegExp(`mcp-use:\\s*\\r?\\n\\s+specifier:\\s*([^\\r\\n]+)\\r?\\n\\s+version:\\s*([^\\r\\n(]+)`, "m")
    );
    if (!specifierBlockMatch) {
      errors.push("Could not locate 'mcp-use' importer entry in pnpm-lock.yaml.");
    } else {
      const lockSpecifier = specifierBlockMatch[1].trim().replace(/^['"]|['"]$/g, "");
      const lockVersion = specifierBlockMatch[2].trim().replace(/^['"]|['"]$/g, "");
      if (lockSpecifier !== expectedMcpUse) {
        errors.push(
          `pnpm-lock.yaml specifier '${lockSpecifier}' for mcp-use does not match package.json '${expectedMcpUse}'.`
        );
      }
      if (lockVersion !== expectedMcpUse) {
        errors.push(
          `pnpm-lock.yaml resolved version '${lockVersion}' for mcp-use does not match pinned '${expectedMcpUse}'.`
        );
      }
    }

    if (!/integrity:\s*sha512-/i.test(lockContent)) {
      errors.push("pnpm-lock.yaml does not contain sha512 package integrity hashes.");
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    mcpUseVersion: expectedMcpUse,
  };
}

const isDirectRun =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) ===
    path.resolve(fileURLToPath(import.meta.url));

if (isDirectRun) {
  const result = verifyDependencies(process.cwd());
  if (!result.ok) {
    console.error("[verify-deps] FAILED:");
    for (const err of result.errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }
  console.log(
    `[verify-deps] PASSED (all dependencies pinned; mcp-use@${result.mcpUseVersion} verified with lockfile sha512 integrity).`
  );
}
