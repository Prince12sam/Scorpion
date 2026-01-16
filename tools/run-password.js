#!/usr/bin/env node

// Legacy Node helper script removed.
// The Node implementation previously depended on ../cli/lib/* which no longer exists.

console.error(
  [
    'This legacy Node helper (tools/run-password.js) has been removed.',
    '',
    'If you need password tooling, use:',
    '  - scorpion bruteforce (for auth testing on authorized targets)',
    '  - dedicated tools like hashcat/john (offline cracking)',
  ].join('\n')
);

process.exit(1);
