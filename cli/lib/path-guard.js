import fs from 'node:fs';
import path from 'node:path';

const WORKSPACE_ROOT = path.resolve(process.env.SCORPION_WORKSPACE_ROOT || process.cwd());
const ALLOW_ABSOLUTE = String(process.env.SCORPION_ALLOW_ABSOLUTE_PATHS || '').toLowerCase() === 'true';

function isInsideRoot(target, root) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export function resolveSafePath(input, options = {}) {
  const {
    mustExist = false,
    description = 'path',
    baseDir = WORKSPACE_ROOT,
    allowOutsideWorkspace = false
  } = options;

  if (typeof input !== 'string' || !input.trim()) {
    throw new Error(`${description} is required`);
  }

  const candidate = path.resolve(path.isAbsolute(input) ? input.trim() : path.join(baseDir, input.trim()));
  const normalizedBase = path.resolve(baseDir);

  if (!ALLOW_ABSOLUTE && !allowOutsideWorkspace && !isInsideRoot(candidate, normalizedBase)) {
    throw new Error(`${description} must stay within ${normalizedBase}`);
  }

  if (mustExist && !fs.existsSync(candidate)) {
    throw new Error(`${description} does not exist: ${candidate}`);
  }

  return candidate;
}

export function ensureSafeDirectory(dirPath, options = {}) {
  const target = resolveSafePath(dirPath, { ...options, description: options.description || 'directory' });
  fs.mkdirSync(target, { recursive: true });
  return target;
}
