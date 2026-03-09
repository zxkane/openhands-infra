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
  // URL-encoded paths: workspace root + optional repo dir name -> "."
  url = url.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject(%2F[^%/]+)?$/gi, '$1/.');
  // Strip workspace prefix from deeper sub-paths
  url = url.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject%2F/gi, '$1/');
  // Non-encoded paths: workspace root + optional repo dir name -> "."
  url = url.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project(\/[^/]+)?$/g, '$1/.');
  // Strip workspace prefix from deeper sub-paths
  url = url.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project\//g, '$1/');
  // Bare repo name (skip if segment contains %2F = multi-segment sub-path)
  url = url.replace(/(\/api\/git\/[^/]+)\/([^/.][^/]*)$/g, function(match, prefix, segment) {
    if (segment.indexOf('%2F') !== -1 || segment.indexOf('%2f') !== -1) {
      return match;
    }
    return prefix + '/.';
  });
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

// Single segment after workspace root is treated as repo name, not sub-path
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject%2Fsrc`),
  `${base}/api/git/changes/.`,
  'URL-encoded /workspace/project/src -> . (single segment = repo name)'
);

// Multi-segment sub-paths are preserved
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject%2Fsrc%2Flib`),
  `${base}/api/git/changes/src%2Flib`,
  'URL-encoded /workspace/project/src/lib -> src%2Flib (multi-segment preserved)'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fopenhands%2Fproject`),
  `${base}/api/git/changes/.`,
  'URL-encoded /openhands/project -> .'
);

// === URL-encoded workspace path + repo directory name (THE ACTUAL BUG) ===
// Frontend sends: %2Fworkspace%2Fproject%2Fopenhands-infra
// After stripping %2Fworkspace%2Fproject%2F, "openhands-infra" remains
// The bare repo name catch-all must normalize it to "."
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject%2Fopenhands-infra`),
  `${base}/api/git/changes/.`,
  'URL-encoded /workspace/project/openhands-infra -> . (not bare openhands-infra)'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject%2Fmy-app`),
  `${base}/api/git/changes/.`,
  'URL-encoded /workspace/project/my-app -> . (not bare my-app)'
);

// === Non-encoded workspace paths (double slash from path joining) ===
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes//workspace/project`),
  `${base}/api/git/changes/.`,
  'non-encoded //workspace/project -> .'
);

// Single segment after workspace root is treated as repo name
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes//workspace/project/lib`),
  `${base}/api/git/changes/.`,
  'non-encoded //workspace/project/lib -> . (single segment = repo name)'
);

// Multi-segment sub-paths are preserved
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes//workspace/project/src/lib`),
  `${base}/api/git/changes/src/lib`,
  'non-encoded //workspace/project/src/lib -> src/lib (multi-segment preserved)'
);

// === Non-encoded workspace path + repo directory name ===
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes//workspace/project/openhands-infra`),
  `${base}/api/git/changes/.`,
  'non-encoded //workspace/project/openhands-infra -> . (not bare openhands-infra)'
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
