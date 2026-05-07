const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path');

async function run() {
  try {
    const outputDir = core.getInput('output-dir') || '/tmp/actionloggr';
    const captureFilter = core.getInput('capture-filter') || '';
    const iocList = core.getInput('ioc-list') || '';
    const webhookUrl = core.getInput('webhook-url') || '';
    const failOnMatch = core.getInput('fail-on-match') || 'false';
    const reportAllTraffic = core.getInput('report-all-traffic') || 'true';

    // Persist all inputs and the action path so post.js can read them.
    // GITHUB_ACTION_PATH is not guaranteed to be set in the post hook context,
    // so we capture it here during main where it is always available.
    core.saveState('action-path', process.env.GITHUB_ACTION_PATH);
    core.saveState('output-dir', outputDir);
    core.saveState('ioc-list', iocList);
    core.saveState('webhook-url', webhookUrl);
    core.saveState('fail-on-match', failOnMatch);
    core.saveState('report-all-traffic', reportAllTraffic);

    // Install system and Python dependencies
    core.startGroup('Install ActionLoggR dependencies');
    await exec.exec(
      'sudo',
      ['apt-get', 'install', '-y', '-qq', 'tcpdump', 'python3-pip', 'conntrack'],
      { ignoreReturnCode: true }
    );
    await exec.exec(
      'pip3',
      ['install', '-q', 'scapy', 'requests'],
      { ignoreReturnCode: true }
    );
    core.endGroup();

    // Use GITHUB_ACTION_PATH so the path remains correct after ncc bundling
    // (__dirname would point into dist/ and scripts/ would not be found there)
    const actionPath = process.env.GITHUB_ACTION_PATH;
    if (!actionPath) {
      throw new Error('GITHUB_ACTION_PATH is not set — cannot locate scripts/');
    }
    const scriptPath = path.join(actionPath, 'scripts', 'monitor-start.sh');

    core.info(`Starting network monitor (output-dir=${outputDir})`);
    await exec.exec('bash', [scriptPath], {
      env: {
        ...process.env,
        ACTIONLOGGR_OUTPUT_DIR: outputDir,
        ACTIONLOGGR_CAPTURE_FILTER: captureFilter,
      },
    });
  } catch (error) {
    core.setFailed(`ActionLoggR main failed: ${error.message}`);
  }
}

run();
