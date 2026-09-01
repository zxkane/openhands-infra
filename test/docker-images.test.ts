import * as fs from 'fs';
import * as path from 'path';

const projectRoot = path.resolve(__dirname, '..');

function read(relativePath: string): string {
  return fs.readFileSync(path.join(projectRoot, relativePath), 'utf8');
}

describe('Docker image patch levels', () => {
  const openHandsDockerfile = read('docker/Dockerfile');
  const openRestyDockerfile = read('docker/openresty/Dockerfile');
  const agentServerDockerfile = read('docker/agent-server-custom/Dockerfile');
  const orchestratorDockerIgnore = read('services/sandbox-orchestrator/.dockerignore');

  test('pins the latest published OpenHands 1.7 image and refreshes Debian packages', () => {
    expect(openHandsDockerfile).toContain('ARG OPENHANDS_VERSION=1.7.0');
    expect(openHandsDockerfile).toContain(
      'ARG OPENHANDS_IMAGE_DIGEST=sha256:916abcb15cc451d96853bd41c55117bb2ff3de0b9914cdcd861d338055798dc6',
    );
    expect(openHandsDockerfile).toContain(
      'FROM docker.openhands.dev/openhands/openhands:${OPENHANDS_VERSION}@${OPENHANDS_IMAGE_DIGEST}',
    );
    expect(openHandsDockerfile).toContain('ARG LAST_UPDATED=2026-09-01');
    expect(openHandsDockerfile).toContain('Refreshing Debian packages as of ${LAST_UPDATED}');
    expect(openHandsDockerfile).toContain('apt-get upgrade -y');
  });

  test('pins OpenResty 1.29.2.5 and refreshes Alpine packages', () => {
    expect(openRestyDockerfile).toContain('ARG OPENRESTY_VERSION=1.29.2.5');
    expect(openRestyDockerfile).toContain(
      'ARG OPENRESTY_IMAGE_DIGEST=sha256:6359d16c2cefedc216861e7092d486bb1ff19548abd1aa71e6dc094c82477aee',
    );
    expect(openRestyDockerfile).toContain(
      'FROM openresty/openresty:${OPENRESTY_VERSION}-alpine-fat@${OPENRESTY_IMAGE_DIGEST}',
    );
    expect(openRestyDockerfile).toContain('ARG LAST_UPDATED=2026-09-01');
    expect(openRestyDockerfile).toContain('Refreshing Alpine packages as of ${LAST_UPDATED}');
    expect(openRestyDockerfile).toContain('apk upgrade --no-cache');
  });

  test('pins agent-server build and runtime bases and upgrades both Debian stages', () => {
    expect(agentServerDockerfile).toContain('ARG PYTHON_VERSION=3.12.14');
    expect(agentServerDockerfile).toContain(
      'ARG PYTHON_IMAGE_DIGEST=sha256:f2431a8cca8c5c6b04bc1309ab7ce99cc36bda0e1787e88a7fac21d9b450a923',
    );
    expect(agentServerDockerfile).toContain(
      'ARG PYTHON_NODEJS_IMAGE=python3.12-nodejs24',
    );
    expect(agentServerDockerfile).toContain(
      'ARG PYTHON_NODEJS_IMAGE_DIGEST=sha256:fd8aec5fe30255946c256309770c6376bf28342e10fce2a3e44dcd9dbf58492d',
    );
    expect(agentServerDockerfile).toContain(
      'FROM python:${PYTHON_VERSION}-slim-bookworm@${PYTHON_IMAGE_DIGEST} AS builder',
    );
    expect(agentServerDockerfile).toContain(
      'FROM nikolaik/python-nodejs:${PYTHON_NODEJS_IMAGE}@${PYTHON_NODEJS_IMAGE_DIGEST}',
    );
    expect(agentServerDockerfile).toContain(
      'ghcr.io/openhands/agent-server:1.19.1-python@sha256:c80c8b0108392f7457bd4cf33bb9917fd9e3bc09f45eeb01fb9ac0822468ffe6',
    );
    expect(agentServerDockerfile).toContain('ARG LAST_UPDATED=2026-09-01');
    expect(agentServerDockerfile.match(/apt-get upgrade -y/g)).toHaveLength(2);
    expect(agentServerDockerfile.match(/Refreshing Debian packages as of \$\{LAST_UPDATED\}/g)).toHaveLength(2);
  });

  test('excludes generated orchestrator content from Docker asset staging', () => {
    expect(orchestratorDockerIgnore).toMatch(/^node_modules$/m);
    expect(orchestratorDockerIgnore).toMatch(/^dist$/m);
    expect(orchestratorDockerIgnore).toMatch(/^test$/m);
    expect(orchestratorDockerIgnore).toMatch(/^\.env\.\*$/m);
  });
});
