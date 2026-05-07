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

    // Persist all inputs so post.js can read them after all job steps complete.
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

    // GITHUB_ACTION_PATH is only available in composite actions, not JS actions.
    // __dirname is the dist/main/ directory after ncc bundling, so two levels up
    // is the action root where scripts/ lives.
    const actionRoot = path.resolve(__dirname, '..', '..');
    const scriptPath = path.join(actionRoot, 'scripts', 'monitor-start.sh');

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
