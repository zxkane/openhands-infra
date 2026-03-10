/**
 * Regression test for patch-fix.js git path normalization.
 *
 * The agent-server WORKDIR is /workspace. When a GitHub repo is connected,
 * the clone lives at /workspace/project/<repo>/. The normalizeGitUrl function
 * must preserve "project/<repo>" in the path so the agent-server resolves to
 * the correct git repository.
 *
 * The frontend sends paths in these forms:
 *   %2Fworkspace%2Fproject%2F<repo>              -> project/<repo> (changes)
 *   %2Fworkspace%2Fproject%2F<repo>%2F<file>     -> project/<repo>/<file> (diff)
 *   <repo>                                       -> project/<repo> (changes)
 *   <repo>%2F<file>                              -> project/<repo>/<file> (diff)
 *   //workspace/project/<repo>                   -> project/<repo> (changes)
 *   //workspace/project/<repo>/<file>            -> project/<repo>/<file> (diff)
 *   %2Fworkspace%2Fproject                       -> . (no repo)
 *   //workspace/project                          -> . (no repo)
 *
 * Run: node docker/test_patch_fix_git_paths.js
 */

// Mirrors the normalizeGitUrl function from patch-fix.js exactly.
function normalizeGitUrl(url) {
  var before = url;
  url = url.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject%2F([^%/]+)(%2F(.*))?$/gi,
    function(match, prefix, ws, repo, hasMore, filePath) {
      if (filePath) { return prefix + '/project/' + repo + '/' + filePath; }
      return prefix + '/project/' + repo;
    });
  url = url.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject$/gi, '$1/.');
  url = url.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project\/([^/]+)(\/(.*))?$/g,
    function(match, prefix, ws, repo, hasMore, filePath) {
      if (filePath) { return prefix + '/project/' + repo + '/' + filePath; }
      return prefix + '/project/' + repo;
    });
  url = url.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project$/g, '$1/.');
  if (url === before) {
    url = url.replace(/(\/api\/git\/[^/]+)\/([^/.][^/]*)$/g, function(match, prefix, segment) {
      var idx = segment.indexOf('%2F');
      if (idx === -1) idx = segment.indexOf('%2f');
      if (idx !== -1) {
        var repo = segment.substring(0, idx);
        var file = segment.substring(idx + 3);
        return prefix + '/project/' + repo + '/' + file;
      }
      return prefix + '/project/' + segment;
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
  `${base}/api/git/changes/project/openhands-infra`,
  'changes: bare repo name -> project/repo'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/my-project`),
  `${base}/api/git/changes/project/my-project`,
  'changes: bare repo name (my-project) -> project/my-project'
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
  `${base}/api/git/changes/project/openhands-infra`,
  'changes: URL-encoded /workspace/project/openhands-infra -> project/openhands-infra'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fworkspace%2Fproject%2Fmy-app`),
  `${base}/api/git/changes/project/my-app`,
  'changes: URL-encoded /workspace/project/my-app -> project/my-app'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fopenhands%2Fproject`),
  `${base}/api/git/changes/.`,
  'changes: URL-encoded /openhands/project -> .'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/changes/%2Fopenhands%2Fproject%2Fmy-repo`),
  `${base}/api/git/changes/project/my-repo`,
  'changes: URL-encoded /openhands/project/my-repo -> project/my-repo'
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
  `${base}/api/git/changes/project/openhands-infra`,
  'changes: non-encoded //workspace/project/openhands-infra -> project/openhands-infra'
);

// =============================================
// DIFF API - URL-encoded workspace + repo + file
// =============================================
// Frontend sends: %2Fworkspace%2Fproject%2Fopenhands-infra%2F.gitignore
// Should become: project/openhands-infra/.gitignore (preserving repo path)
assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/%2Fworkspace%2Fproject%2Fopenhands-infra%2F.gitignore`),
  `${base}/api/git/diff/project/openhands-infra/.gitignore`,
  'diff: URL-encoded /workspace/project/repo/.gitignore -> project/repo/.gitignore'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/%2Fworkspace%2Fproject%2Fopenhands-infra%2Fsrc%2Findex.ts`),
  `${base}/api/git/diff/project/openhands-infra/src%2Findex.ts`,
  'diff: URL-encoded /workspace/project/repo/src/index.ts -> project/repo/src%2Findex.ts'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/%2Fworkspace%2Fproject%2Fmy-app%2FREADME.md`),
  `${base}/api/git/diff/project/my-app/README.md`,
  'diff: URL-encoded /workspace/project/my-app/README.md -> project/my-app/README.md'
);

// =============================================
// DIFF API - non-encoded workspace + repo + file
// =============================================
assertEqual(
  normalizeGitUrl(`${base}/api/git/diff//workspace/project/openhands-infra/.gitignore`),
  `${base}/api/git/diff/project/openhands-infra/.gitignore`,
  'diff: non-encoded //workspace/project/repo/.gitignore -> project/repo/.gitignore'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff//workspace/project/openhands-infra/src/index.ts`),
  `${base}/api/git/diff/project/openhands-infra/src/index.ts`,
  'diff: non-encoded //workspace/project/repo/src/index.ts -> project/repo/src/index.ts'
);

// =============================================
// DIFF API - bare repo name + file
// =============================================
// Frontend sends: openhands-infra%2F.gitignore (from user's report)
assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/openhands-infra%2F.gitignore`),
  `${base}/api/git/diff/project/openhands-infra/.gitignore`,
  'diff: bare repo%2F.gitignore -> project/repo/.gitignore'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/openhands-infra%2Fproject%2Fopenhands-infra`),
  `${base}/api/git/diff/project/openhands-infra/project%2Fopenhands-infra`,
  'diff: bare repo%2Fproject%2Frepo -> project/repo/project%2Frepo'
);

assertEqual(
  normalizeGitUrl(`${base}/api/git/diff/some-repo`),
  `${base}/api/git/diff/project/some-repo`,
  'diff: bare repo name only -> project/repo'
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
