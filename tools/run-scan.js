#!/usr/bin/env node

// Legacy Node helper script removed.
// The Node implementation previously depended on ../cli/lib/* which no longer exists.
// Use the Python CLI instead.

console.error(
  [
    'This legacy Node helper (tools/run-scan.js) has been removed.',
    '',
    'Use:',
    '  scorpion scan <host> --ports 1-1000 --output results/scan.json',
  ].join('\n')
);

process.exit(1);

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
