#!/usr/bin/env node

// Legacy Node helper script removed.
// The Node implementation previously depended on ../cli/lib/* which no longer exists.
// Use the Python CLI instead.

console.error(
  [
    'This legacy Node helper (tools/run-recon.js) has been removed.',
    '',
    'Use:',
    '  scorpion recon <host> --output results/recon.json',
  ].join('\n')
);

process.exit(1);
