#!/usr/bin/env node

// Legacy Node helper script removed.
// The Node implementation previously depended on ../cli/lib/* which no longer exists.
// Use the Python CLI instead.

console.error(
  [
    'This legacy Node helper (tools/run-suite.js) has been removed.',
    '',
    'Use:',
    '  scorpion suite <target> --profile web --mode active --output-dir results',
  ].join('\n')
);

process.exit(1);
