import { defineConfig } from '@playwright/test';

/**
 * Real Chrome (the installed Google Chrome, no browser download). One worker, one long test: the scenes of
 * docs/VIDEO-SCRIPT.md in order. Videos, the timeline and the log go to ./out (git-ignored).
 * VIDEO_PACE scales every pause (1 = the script's timing, 0.2 = a quick rehearsal). HEADED=1 shows the window.
 */
const pace = Number(process.env.VIDEO_PACE ?? 1);

export default defineConfig({
  testDir: '.',
  testMatch: 'record.spec.ts',
  outputDir: 'out/test-results',
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 25 * 60_000,
  reporter: [['list']],
  use: {
    channel: 'chrome',
    headless: !process.env.HEADED,
    launchOptions: { slowMo: Math.round(250 * pace) },
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
});
