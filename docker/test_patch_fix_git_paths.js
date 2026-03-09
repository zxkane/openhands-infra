/**
 * Regression test for patch-fix.js git path normalization.
 *
 * The agent-server git router expects "." for the workspace root.
 * The frontend may send various path formats that need normalizing:
 *   - /workspace/project  (absolute workspace path)
 *   - %2Fworkspace%2Fproject  (URL-encoded)
 *   - repo-name  (bare GitHub repo name)
 *
 * Run: node docker/test_patch_fix_git_paths.js
 */

// Mirrors the normalizeGitUrl function from patch-fix.js exactly.
function normalizeGitUrl(url) {
  var before = url;
  // URL-encoded paths
  url = url.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject$/gi, '$1/.');
  url = url.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject%2F/gi, '$1/');
  // Non-encoded paths
  url = url.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project$/g, '$1/.');
  url = url.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project\//g, '$1/');
  // Bare repo name -- only if no workspace rewrite above changed the URL
  if (url === before) {
    url = url.replace(/(\/api\/git\/[^/]+)\/([^/.][^/]*)$/g, '$1/.');
  }
  return url;
}

let passed = 0;
let failed = 0;

function assertEqual(actual, expected, description) {
  if (actual === expected) {
    passed++;
  } else {
    failed++;
    console.error(`FAIL: ${description}`);
    console.error(`  expected: ${expected}`);
    console.error(`  actual:   ${actual}`);
  }
}

const base = 'https://example.com/runtime/abc123/4443';

// === Bare repo name (the bug being fixed) ===
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/openhands-infra`),
  `${base}/api/git/changes/.`,
  'bare repo name: openhands-infra -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/my-project`),
  `${base}/api/git/changes/.`,
  'bare repo name: my-project -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/some-repo`),
  `${base}/api/git/diff/.`,
  'bare repo name with diff action'
);

// Already-correct "." path should not be changed
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/.`),
  `${base}/api/git/changes/.`,
  'already "." should not change'
);

// === URL-encoded workspace paths ===
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject`),
  `${base}/api/git/changes/.`,
  'URL-encoded /workspace/project -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject%2Fsrc`),
  `${base}/api/git/changes/src`,
  'URL-encoded /workspace/project/src -> src'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fopenhands%2Fproject`),
  `${base}/api/git/changes/.`,
  'URL-encoded /openhands/project -> .'
);

// === Non-encoded workspace paths (double slash from path joining) ===
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes//workspace/project`),
  `${base}/api/git/changes/.`,
  'non-encoded //workspace/project -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes//workspace/project/lib`),
  `${base}/api/git/changes/lib`,
  'non-encoded //workspace/project/lib -> lib'
);

// === Non-git API paths should not be affected ===
assertEqual(
  normalizeGitUrl(`${base}/api/conversations/abc123`),
  `${base}/api/conversations/abc123`,
  'non-git API path should not change'
);

// Summary
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
