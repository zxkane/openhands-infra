import * as fs from 'fs';
import * as path from 'path';

const projectRoot = path.resolve(__dirname, '..');
const script = fs.readFileSync(
  path.join(projectRoot, 'scripts/generate-soci-index.sh'),
  'utf8',
);

describe('SOCI index generation script', () => {
  test('validates a tagged private ECR image before requesting credentials', () => {
    const validationIndex = script.indexOf(
      'if [[ ! "${IMAGE_URI}" =~ ${ECR_IMAGE_PATTERN} ]]',
    );
    const credentialIndex = script.indexOf('aws ecr get-login-password');

    expect(validationIndex).toBeGreaterThan(0);
    expect(credentialIndex).toBeGreaterThan(validationIndex);
    expect(script).toContain('IMAGE_REGION="${BASH_REMATCH[2]}"');
    expect(script).toContain('REGION="${REGION:-${IMAGE_REGION}}"');
    expect(script).toContain(
      'ERROR: Region ${REGION} does not match image region ${IMAGE_REGION}',
    );
  });

  test('enforces ECR repository and derived SOCI tag limits', () => {
    expect(script).toContain('${#REPOSITORY_NAME} < 2 || ${#REPOSITORY_NAME} > 256');
    expect(script).toContain('${#SOURCE_TAG} > 123');
    expect(script.indexOf('SOCI_IMAGE_URI="${IMAGE_URI}-soci"')).toBeGreaterThan(
      script.indexOf('${#SOURCE_TAG} > 123'),
    );
  });

  test('passes ECR credentials through stdin and removes the temporary config', () => {
    expect(script).toContain('aws ecr get-login-password --region "${REGION}" |');
    expect(script).toContain('--username AWS --password-stdin "${REGISTRY}"');
    expect(script).toContain('DOCKER_CONFIG_DIR=$(mktemp -d)');
    expect(script).toContain('trap cleanup EXIT');
    expect(script).toContain('sudo find "${DOCKER_CONFIG_DIR}" -depth -delete');
    expect(script).not.toContain('ECR_CREDS_FILE');
    expect(script).not.toMatch(/(?:ctr|nerdctl).*--user\b/);
  });

  test('uses the authenticated temporary config for pull and push', () => {
    expect(script.match(/DOCKER_CONFIG="\$\{DOCKER_CONFIG_DIR\}"/g)).toHaveLength(3);
    expect(script).toContain('nerdctl --namespace default pull "${IMAGE_URI}"');
    expect(script).toContain('nerdctl --namespace default push "${SOCI_IMAGE_URI}"');
  });

  test('removes only images that were not already present locally', () => {
    expect(script).toContain('SOURCE_IMAGE_WAS_PRESENT=false');
    expect(script).toContain('SOCI_IMAGE_WAS_PRESENT=false');
    expect(script).toContain('if [ "${SOURCE_IMAGE_WAS_PRESENT}" = false ]; then');
    expect(script).toContain('if [ "${SOCI_IMAGE_WAS_PRESENT}" = false ]; then');
  });
});
