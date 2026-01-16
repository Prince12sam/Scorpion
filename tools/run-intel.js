#!/usr/bin/env node

// Legacy Node helper script removed.
// The Node implementation previously depended on ../cli/lib/* which no longer exists.
// Use the Python threat intel module instead.

console.error(
  [
    'This legacy Node helper (tools/run-intel.js) has been removed.',
    '',
    'If you have python_scorpion installed, use:',
    '  python -m python_scorpion.threat_intel <indicator>',
  ].join('\n')
);

process.exit(1);
