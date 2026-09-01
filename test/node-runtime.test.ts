import * as fs from 'fs';
import * as path from 'path';

const projectRoot = path.resolve(__dirname, '..');

function read(relativePath: string): string {
  return fs.readFileSync(path.join(projectRoot, relativePath), 'utf8');
}

describe('Node.js runtime alignment', () => {
  test('local development and package metadata require Node.js 24', () => {
    const packageJson = JSON.parse(read('package.json'));
    const orchestratorPackageJson = JSON.parse(
      read('services/sandbox-orchestrator/package.json'),
    );

    expect(read('.nvmrc').trim()).toBe('24');
    expect(packageJson.engines.node).toBe('>=24');
    expect(packageJson.devDependencies['@types/node']).toMatch(/^\^24\./);
    expect(orchestratorPackageJson.engines.node).toBe('>=24');
    expect(orchestratorPackageJson.devDependencies['@types/node']).toMatch(/^\^24\./);
    expect(read('docker/agent-server-custom/Dockerfile')).toContain(
      'ARG PYTHON_NODEJS_IMAGE=python3.12-nodejs24',
    );
    expect(read('README.md')).toContain('Node.js 24 LTS and npm');
    expect(read('test/E2E_TEST_CASES.md')).toContain('Node.js 24 LTS installed');
  });

  test.each([
    '.github/workflows/ci.yml',
    '.github/workflows/release-prepare.yml',
    '.github/workflows/security-scan.yml',
  ])('%s uses Node.js 24 for every npm job', (workflowPath) => {
    const workflow = read(workflowPath);
    const configuredVersions = Array.from(
      workflow.matchAll(/node-version:\s*['"]?([^'"\s]+)['"]?/g),
      (match) => match[1],
    );
    const jobsSection = workflow.slice(workflow.indexOf('\njobs:\n') + 7);
    const jobs = Array.from(
      jobsSection.matchAll(
        /^  ([a-zA-Z0-9_-]+):\n([\s\S]*?)(?=^  [a-zA-Z0-9_-]+:\n|(?![\s\S]))/gm,
      ),
      (match) => ({ name: match[1], body: match[2] }),
    );
    const npmJobs = jobs.filter(({ body }) =>
      /\bnpm (?:ci|install|run|test|audit|version)\b/.test(body),
    );

    expect(configuredVersions.length).toBeGreaterThan(0);
    expect(new Set(configuredVersions)).toEqual(new Set(['24']));
    expect(npmJobs.length).toBeGreaterThan(0);
    for (const job of npmJobs) {
      expect(job.body).toContain('uses: actions/setup-node@');
      expect(job.body).toMatch(/node-version:\s*['"]?24['"]?/);
    }
  });
});
