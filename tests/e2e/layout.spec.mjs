// Layout at phone, tablet and desktop widths in both themes: no horizontal scrolling, everything reachable,
// dialogs inside the screen.
// SPDX-License-Identifier: MIT
import { test, expect } from '@playwright/test';

const WIDTHS = [320, 390, 768, 1280, 1440];
for (const width of WIDTHS) {
  for (const scheme of ['light', 'dark']) {
    test(`${width}px wide, ${scheme}: no sideways scrolling and the dialogs fit`, async ({ page, baseURL }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto(baseURL);
      await page.waitForSelector('html[data-ready="1"]');
      await page.click('#sample-button');
      await expect(page.locator('#results')).toBeVisible();
      const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(over).toBeLessThanOrEqual(0);
      for (const id of ['#open-button', '#recent-button', '#sample-button', '#report-button', '#theme-toggle', '#about-button']) await expect(page.locator(id)).toBeVisible();
      const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
      expect(bg).toBe(scheme === 'dark' ? 'rgb(16, 19, 17)' : 'rgb(245, 244, 239)');
      for (const [open, dialog, close] of [['#report-button', '#report-dialog', '#report-close'], ['#about-button', '#about-dialog', '#about-close'], ['#recent-button', '#recent-dialog', '#recent-close']]) {
        await page.click(open);
        const box = await page.locator(dialog).boundingBox();
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(width);
        await page.click(close);
      }
    });
  }
}

test.describe('on a touch phone', () => {
  test.skip(({ browserName }) => browserName === 'firefox', 'Firefox has no mobile emulation');
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  test('taps work and nothing scrolls sideways', async ({ page, baseURL }) => {
    await page.goto(baseURL);
    await page.waitForSelector('html[data-ready="1"]');
    await page.tap('#sample-button');
    await expect(page.locator('#verdict h2')).toContainText('Possible impersonation');
    await page.tap('#report-button');
    await expect(page.locator('#report-dialog')).toHaveAttribute('open', '');
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
  });
});
