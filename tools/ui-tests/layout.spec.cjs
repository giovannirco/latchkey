// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, login, visit, FRONT_DOOR } = require('./support.cjs');

const lock = encodeURIComponent(FRONT_DOOR);
const SCREENS = [
  '#/locks',
  `#/lock/${lock}/access`,
  `#/lock/${lock}/settings`,
  `#/lock/${lock}/log`,
  `#/lock/${lock}/device`,
  '#/pair',
  '#/security',
  '#/system',
];

async function overflow(page) {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

test.describe('phone width', () => {
  test.use({ viewport: { width: 360, height: 740 }, isMobile: true, hasTouch: true });

  test('every screen fits 360 px without horizontal scrolling', async ({ page }) => {
    await login(page);
    for (const screen of SCREENS) {
      await visit(page, screen);
      expect(await overflow(page), screen).toBeLessThanOrEqual(0);
    }
  });
});

test('the page renders in standards mode with one main landmark per screen', async ({ page }) => {
  await page.goto('/');
  expect(await page.evaluate(() => document.compatMode)).toBe('CSS1Compat');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await login(page);
  for (const screen of SCREENS) {
    await visit(page, screen);
    await expect(page.getByRole('main')).toHaveCount(1);
    await expect(page.locator('#main h1')).toHaveCount(1);
  }
});

test('dark mode follows the system preference', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('/');
  const light = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await page.emulateMedia({ colorScheme: 'dark' });
  const dark = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(dark).not.toBe(light);
});

test('every form control has an accessible name', async ({ page }) => {
  await login(page);
  for (const screen of SCREENS) {
    await visit(page, screen);
    const unnamed = await page.evaluate(() =>
      [...document.querySelectorAll('#main input, #main select, #main textarea, #main button')]
        .filter(
          (el) =>
            !el.labels?.length &&
            !el.getAttribute('aria-label') &&
            !el.getAttribute('aria-labelledby') &&
            !el.textContent.trim(),
        )
        .map((el) => el.outerHTML.slice(0, 80)),
    );
    expect(unnamed, screen).toEqual([]);
  }
});
