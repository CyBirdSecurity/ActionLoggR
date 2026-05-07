const core = require('@actions/core');
const exec = require('@actions/exec');
const github = require('@actions/github');
const artifact = require('@actions/artifact');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

async function run() {
  try {
    // Retrieve all values that were saved by main.js
    const outputDir = core.getState('output-dir') || '/tmp/actionloggr';
    const iocList = core.getState('ioc-list') || '';
    const webhookUrl = core.getState('webhook-url') || '';
    const failOnMatch = core.getState('fail-on-match') || 'false';
    const reportAllTraffic = core.getState('report-all-traffic') || 'true';

    // Same logic as main.js — __dirname is dist/post/ after ncc bundling.
    const actionRoot = path.resolve(__dirname, '..', '..');
    const scriptPath = path.join(actionRoot, 'scripts', 'monitor-stop.sh');

    core.info('Stopping network monitor and generating report…');
    await exec.exec('bash', [scriptPath], {
      env: {
        ...process.env,
        ACTIONLOGGR_OUTPUT_DIR: outputDir,
        ACTIONLOGGR_IOC_LIST: iocList,
        ACTIONLOGGR_WEBHOOK_URL: webhookUrl,
        ACTIONLOGGR_REPORT_ALL: reportAllTraffic,
        // Pass through OIDC token vars so the script can authenticate webhooks
        ACTIONS_ID_TOKEN_REQUEST_URL: process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '',
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '',
      },
    });

    // Parse the report to count IoC matches
    const reportPath = path.join(outputDir, 'report.json');
    const sarifPath = path.join(outputDir, 'results.sarif');

    let iocMatches = 0;
    if (fs.existsSync(reportPath)) {
      try {
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        iocMatches = Array.isArray(report.ioc_matches) ? report.ioc_matches.length : 0;
      } catch (e) {
        core.warning(`Could not parse report.json: ${e.message}`);
      }
    }

    // Set action outputs
    core.setOutput('report-path', reportPath);
    core.setOutput('sarif-path', sarifPath);
    core.setOutput('ioc-matches', String(iocMatches));

    // Upload report as a workflow artifact so it survives after the job ends.
    // This runs from the post hook (after all job steps) so we must upload here —
    // any upload-artifact step the user adds runs before the report is generated.
    try {
      const files = fs.readdirSync(outputDir)
        .map(f => path.join(outputDir, f));
      if (files.length > 0) {
        const client = artifact.create();
        await client.uploadArtifact(
          'actionloggr-report',
          files,
          outputDir,
          { retentionDays: 90 }
        );
        core.info('ActionLoggR report uploaded as artifact actionloggr-report');
      }
    } catch (e) {
      core.warning(`Artifact upload failed: ${e.message}`);
    }

    // Upload SARIF to GitHub Security tab when IoC matches exist
    if (iocMatches > 0 && fs.existsSync(sarifPath)) {
      try {
        const token = core.getInput('github-token') || process.env.GITHUB_TOKEN;
        if (!token) {
          core.warning('No github-token available — skipping SARIF upload');
        } else {
          const octokit = github.getOctokit(token);
          const { owner, repo } = github.context.repo;
          const commitSha = github.context.sha;
          const ref = github.context.ref;

          const sarifContent = fs.readFileSync(sarifPath);
          const gzipped = zlib.gzipSync(sarifContent);
          const sarifBase64 = gzipped.toString('base64');

          await octokit.rest.codeScanning.uploadSarif({
            owner,
            repo,
            commit_sha: commitSha,
            ref,
            sarif: sarifBase64,
            tool_name: 'ActionLoggR',
          });
          core.info('SARIF uploaded to GitHub Security tab');
        }
      } catch (e) {
        // Non-fatal: user may not have security-events: write permission
        core.warning(`SARIF upload failed (security-events: write may be required): ${e.message}`);
      }
    }

    // Fail the job if configured and matches were found
    if (failOnMatch === 'true' && iocMatches > 0) {
      core.setFailed(
        `ActionLoggR detected ${iocMatches} IoC match(es). See report at ${reportPath}`
      );
    }
  } catch (error) {
    core.setFailed(`ActionLoggR post failed: ${error.message}`);
  }
}

run();
