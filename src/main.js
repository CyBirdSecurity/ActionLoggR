const core = require('@actions/core');
const { spawnSync } = require('child_process');
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
    spawnSync('sudo', ['apt-get', 'install', '-y', '-qq', 'tcpdump', 'python3-pip', 'conntrack'], { stdio: 'inherit' });
    spawnSync('pip3', ['install', '-q', 'scapy', 'requests'], { stdio: 'inherit' });
    core.endGroup();

    // __dirname is dist/main/ after ncc bundling; two levels up is the action root.
    const actionRoot = path.resolve(__dirname, '..', '..');
    const scriptPath = path.join(actionRoot, 'scripts', 'monitor-start.sh');

    core.info(`Starting network monitor (output-dir=${outputDir})`);

    // Use spawnSync with stdio:'inherit' instead of exec.exec.
    // exec.exec creates stdout/stderr pipes; the long-running background processes
    // spawned by monitor-start.sh (tcpdump, dmesg, conntrack) would inherit those
    // pipes and keep them open, causing exec.exec to hang indefinitely.
    // With stdio:'inherit', no pipes are created — the script output flows through
    // the runner's own stdout/stderr and there is nothing for background processes
    // to hold open.
    const result = spawnSync('bash', [scriptPath], {
      env: {
        ...process.env,
        ACTIONLOGGR_OUTPUT_DIR: outputDir,
        ACTIONLOGGR_CAPTURE_FILTER: captureFilter,
      },
      stdio: 'inherit',
    });
    if (result.status !== 0) {
      throw new Error(`monitor-start.sh exited with code ${result.status}`);
    }
  } catch (error) {
    core.setFailed(`ActionLoggR main failed: ${error.message}`);
  }
}

run();
