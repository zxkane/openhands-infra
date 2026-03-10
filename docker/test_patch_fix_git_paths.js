/**
 * Regression test for patch-fix.js git path normalization.
 *
 * The agent-server git router expects "." for the workspace root,
 * or file paths relative to the workspace root for diff requests.
 *
 * The frontend sends paths in these forms:
 *   %2Fworkspace%2Fproject%2F<repo>              -> "." (changes)
 *   %2Fworkspace%2Fproject%2F<repo>%2F<file>     -> <file> (diff)
 *   <repo>                                       -> "." (changes)
 *   <repo>%2F<file>                              -> <file> (diff)
 *   //workspace/project/<repo>                   -> "." (changes)
 *   //workspace/project/<repo>/<file>            -> <file> (diff)
 *
 * Run: node docker/test_patch_fix_git_paths.js
 */

// Mirrors the normalizeGitUrl function from patch-fix.js exactly.
function normalizeGitUrl(url) {
  var before = url;
  url = url.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject%2F([^%/]+)(%2F(.*))?$/gi,
    function(match, prefix, ws, repo, hasMore, filePath) {
      if (filePath) { return prefix + '/' + filePath; }
      return prefix + '/.';
    });
  url = url.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject$/gi, '$1/.');
  url = url.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project\/([^/]+)(\/(.*))?$/g,
    function(match, prefix, ws, repo, hasMore, filePath) {
      if (filePath) { return prefix + '/' + filePath; }
      return prefix + '/.';
    });
  url = url.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project$/g, '$1/.');
  if (url === before) {
    url = url.replace(/(\/api\/git\/[^/]+)\/([^/.][^/]*)$/g, function(match, prefix, segment) {
      var idx = segment.indexOf('%2F');
      if (idx === -1) idx = segment.indexOf('%2f');
      if (idx !== -1) { return prefix + '/' + segment.substring(idx + 3); }
      return prefix + '/.';
    });
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

// =============================================
// CHANGES API - bare repo name
// =============================================
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/openhands-infra`),
  `${base}/api/git/changes/.`,
  'changes: bare repo name -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/my-project`),
  `${base}/api/git/changes/.`,
  'changes: bare repo name (my-project) -> .'
);

// Already-correct "." path should not be changed
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/.`),
  `${base}/api/git/changes/.`,
  'changes: already "." should not change'
);

// =============================================
// CHANGES API - URL-encoded workspace paths
// =============================================
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject`),
  `${base}/api/git/changes/.`,
  'changes: URL-encoded /workspace/project -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject%2Fopenhands-infra`),
  `${base}/api/git/changes/.`,
  'changes: URL-encoded /workspace/project/openhands-infra -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject%2Fmy-app`),
  `${base}/api/git/changes/.`,
  'changes: URL-encoded /workspace/project/my-app -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fopenhands%2Fproject`),
  `${base}/api/git/changes/.`,
  'changes: URL-encoded /openhands/project -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fopenhands%2Fproject%2Fmy-repo`),
  `${base}/api/git/changes/.`,
  'changes: URL-encoded /openhands/project/my-repo -> .'
);

// =============================================
// CHANGES API - non-encoded workspace paths
// =============================================
assertEqual(
  normalizeGitUrl(`${base}/api/git/changes//workspace/project`),
  `${base}/api/git/changes/.`,
  'changes: non-encoded //workspace/project -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes//workspace/project/openhands-infra`),
  `${base}/api/git/changes/.`,
  'changes: non-encoded //workspace/project/openhands-infra -> .'
);

// =============================================
// DIFF API - URL-encoded workspace + repo + file (THE ACTUAL BUG)
// =============================================
// Frontend sends: %2Fworkspace%2Fproject%2Fopenhands-infra%2F.gitignore
// Should become: .gitignore (file relative to workspace root)
assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/%2Fworkspace%2Fproject%2Fopenhands-infra%2F.gitignore`),
  `${base}/api/git/diff/.gitignore`,
  'diff: URL-encoded /workspace/project/repo/.gitignore -> .gitignore'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/%2Fworkspace%2Fproject%2Fopenhands-infra%2Fsrc%2Findex.ts`),
  `${base}/api/git/diff/src%2Findex.ts`,
  'diff: URL-encoded /workspace/project/repo/src/index.ts -> src%2Findex.ts'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/%2Fworkspace%2Fproject%2Fmy-app%2FREADME.md`),
  `${base}/api/git/diff/README.md`,
  'diff: URL-encoded /workspace/project/my-app/README.md -> README.md'
);

// =============================================
// DIFF API - non-encoded workspace + repo + file
// =============================================
assertEqual(
  normalizeGitUrl(`${base}/api/git/diff//workspace/project/openhands-infra/.gitignore`),
  `${base}/api/git/diff/.gitignore`,
  'diff: non-encoded //workspace/project/repo/.gitignore -> .gitignore'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff//workspace/project/openhands-infra/src/index.ts`),
  `${base}/api/git/diff/src/index.ts`,
  'diff: non-encoded //workspace/project/repo/src/index.ts -> src/index.ts'
);

// =============================================
// DIFF API - bare repo name + file
// =============================================
// Frontend sends: openhands-infra%2F.gitignore (from user's report)
assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/openhands-infra%2F.gitignore`),
  `${base}/api/git/diff/.gitignore`,
  'diff: bare repo%2F.gitignore -> .gitignore'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/openhands-infra%2Fproject%2Fopenhands-infra`),
  `${base}/api/git/diff/project%2Fopenhands-infra`,
  'diff: bare repo%2Fproject%2Frepo -> project%2Frepo'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/some-repo`),
  `${base}/api/git/diff/.`,
  'diff: bare repo name only -> .'
);

// =============================================
// Non-git API paths should not be affected
// =============================================
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
