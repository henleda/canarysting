import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

type FixtureIDs = {
  trace_id: string;
  not_found_trace_id: string;
  unavailable_trace_id: string;
  malformed_trace_id: string;
  invalid_evidence_id: string;
  invalid_json_id: string;
  zero_candidate_id: string;
  zero_duration_id: string;
  held_without_hold_id: string;
  duplicate_hold_id: string;
  invalid_join_id: string;
};

async function fixtureIDs(request: APIRequestContext): Promise<FixtureIDs> {
  const response = await request.get('/api/test/trace-fixture');
  expect(response.ok()).toBeTruthy();
  return response.json() as Promise<FixtureIDs>;
}

async function openTrace(page: Page, traceID: string) {
  await page.goto(`/traces/${encodeURIComponent(traceID)}`);
}

test('loads the canonical Go projection and explains a partial, conflicted trace', async ({ page, request }) => {
  const ids = await fixtureIDs(request);
  let releaseTrace!: () => void;
  const traceGate = new Promise<void>((resolve) => { releaseTrace = resolve; });
  await page.route((url) => url.pathname.startsWith('/api/traces/'), async (route) => {
    await traceGate;
    await route.continue();
  });

  const projectedResponse = page.waitForResponse((response) =>
    response.url().includes('/api/traces/') && response.status() === 200,
  );
  const navigation = openTrace(page, ids.trace_id);
  await expect(page.getByRole('heading', { level: 1, name: 'Loading security trace…' })).toBeVisible();
  await expect(page.getByRole('status')).toHaveText('Loading security trace');
  releaseTrace();
  await navigation;
  const projectedJSON = await (await projectedResponse).json() as {
    trace_id?: string;
    scenario_id?: string;
    explanation?: { joins?: Array<{ candidate?: { id?: string; schema_version?: number }; key_fingerprint?: string }> };
  };
  expect(projectedJSON.trace_id).toBe(ids.trace_id);
  expect(projectedJSON.scenario_id).toBe('m2b5-operator-conflict');
  const projectedJoins = projectedJSON.explanation?.joins ?? [];
  expect(projectedJoins).toHaveLength(4);
  const identities = projectedJoins.map((join) => `${join.candidate?.id}:v${join.candidate?.schema_version}:${join.key_fingerprint}`);
  expect(new Set(identities).size).toBe(4);
  expect(projectedJoins.every((join) => Boolean(join.key_fingerprint))).toBeTruthy();

  await expect(page.getByRole('heading', { level: 1, name: 'Conflicting evidence across Checkout API and Payments' })).toBeVisible();
  await expect(page.getByRole('status')).toHaveText(/Security trace loaded: Conflicting evidence across Checkout API and Payments/);
  await expect(page.getByLabel('Trace status: Conflicted')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What happened' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Why CanaryView believes this' })).toBeVisible();
  await expect(page.getByText('Bounded · 2.25s trace window', { exact: true })).toBeVisible();
  await expect(page.getByText(/Bounded \(±250ms\)/)).toBeVisible();
  await expect(page.getByText('Policy decision · cilium-policy-allow · schema v3', { exact: true })).toBeVisible();
  await expect(page.getByText('Policy decision · cilium-policy-allow · schema v4', { exact: true })).toBeVisible();
  await expect(page.getByText('Partial coverage', { exact: true })).toBeVisible();
  await expect(page.getByText('Conflicting evidence', { exact: true })).toBeVisible();
  await expect(page.getByText('This workspace is read-only and cannot trigger or change a response.')).toBeVisible();
  await expect(page.locator('.trace-joins > li')).toHaveCount(4);
  await page.getByText('Technical citations').first().click();
  await expect(page.getByText('Key fingerprint', { exact: true }).first()).toBeVisible();

  await page.getByText('Trace lifecycle and technical scope').click();
  await expect(page.locator('.trace-lifecycle').getByText('Legal hold', { exact: true })).toBeVisible();
  await expect(page.locator('.trace-lifecycle').getByText('None', { exact: true })).toBeVisible();

  await page.getByText('Technical references').last().click();
  await expect(page.getByText('evidence-policy-conflict · schema v3', { exact: true })).toBeVisible();

  const evidenceButton = page.getByRole('button', { name: 'View raw reference for Gateway Request' });
  await expect(evidenceButton).toBeVisible();
  await evidenceButton.click();

  const drawer = page.getByRole('dialog', { name: 'Evidence details' });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText('Integrity mismatch', { exact: true })).toBeVisible();
  await expect(drawer.getByText('Source-owned reference', { exact: true })).toBeVisible();
  await expect(drawer.getByText('Source-owned; not represented by this trace projection', { exact: true })).toBeVisible();
  await expect(drawer.getByRole('heading', { name: 'Trace projection lifecycle' })).toBeVisible();
  await expect(drawer.getByText('Supporting', { exact: true })).toHaveCount(0);
  await expect(drawer.getByText('No source payload is stored in this workspace.')).toBeVisible();

  await page.keyboard.press('Escape');
  await expect(drawer).not.toBeVisible();
  await expect(evidenceButton).toBeFocused();
});

test('supports the raw-reference path using only sequential keyboard navigation', async ({ page, request }) => {
  const ids = await fixtureIDs(request);
  await openTrace(page, ids.trace_id);
  const evidenceButton = page.getByRole('button', { name: 'View raw reference for Gateway Request' });
  await expect(evidenceButton).toBeVisible();

  for (let presses = 0; presses < 40; presses += 1) {
    if (await evidenceButton.evaluate((element) => element === document.activeElement)) break;
    await page.keyboard.press('Tab');
  }
  await expect(evidenceButton).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog', { name: 'Evidence details' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(evidenceButton).toBeFocused();
});

for (const terminal of [
  {
    id: 'not_found_trace_id' as const,
    heading: 'Security trace not found',
    nextStep: 'Verify the trace link and scope',
  },
  {
    id: 'unavailable_trace_id' as const,
    heading: 'Security trace unavailable',
    nextStep: 'Retry after the trace query service recovers',
  },
  {
    id: 'malformed_trace_id' as const,
    heading: 'Security trace could not be read',
    nextStep: 'check the dashboard-backend trace route and projection logs',
  },
  {
    id: 'invalid_evidence_id' as const,
    heading: 'Security trace could not be read',
    nextStep: 'check the dashboard-backend trace route and projection logs',
  },
  {
    id: 'invalid_json_id' as const,
    heading: 'Security trace could not be read',
    nextStep: 'check the dashboard-backend trace route and projection logs',
  },
  {
    id: 'zero_candidate_id' as const,
    heading: 'Security trace could not be read',
    nextStep: 'check the dashboard-backend trace route and projection logs',
  },
  {
    id: 'zero_duration_id' as const,
    heading: 'Security trace could not be read',
    nextStep: 'check the dashboard-backend trace route and projection logs',
  },
  {
    id: 'held_without_hold_id' as const,
    heading: 'Security trace could not be read',
    nextStep: 'check the dashboard-backend trace route and projection logs',
  },
  {
    id: 'duplicate_hold_id' as const,
    heading: 'Security trace could not be read',
    nextStep: 'check the dashboard-backend trace route and projection logs',
  },
  {
    id: 'invalid_join_id' as const,
    heading: 'Security trace could not be read',
    nextStep: 'check the dashboard-backend trace route and projection logs',
  },
]) {
  test(`renders an explicit terminal state for ${terminal.id}`, async ({ page, request }) => {
    const ids = await fixtureIDs(request);
    await openTrace(page, ids[terminal.id]);
    const alert = page.locator('.trace-load-failure');
    await expect(alert.getByRole('heading', { level: 1, name: terminal.heading })).toBeVisible();
    await expect(alert).toContainText(terminal.nextStep);
    await expect(page.getByText('Loading security trace…')).toHaveCount(0);
    await expect(page.locator('.trace-workspace')).toHaveCount(0);
  });
}

test('reflows at 320 CSS pixels and keeps essential trace text at AA contrast', async ({ page, request }) => {
  const ids = await fixtureIDs(request);
  await page.setViewportSize({ width: 320, height: 900 });
  await openTrace(page, ids.trace_id);
  await expect(page.locator('.trace-workspace')).toBeVisible();

  const widths = await page.evaluate(() => ({
    document: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
    navigation: document.querySelector('.sidenav')!.scrollWidth - document.querySelector('.sidenav')!.clientWidth,
  }));
  expect(widths.document).toBeLessThanOrEqual(1);
  expect(widths.body).toBeLessThanOrEqual(1);
  expect(widths.navigation).toBeLessThanOrEqual(1);

  const evidenceButton = page.getByRole('button', { name: 'View raw reference for Gateway Request' });
  const buttonBox = await evidenceButton.boundingBox();
  expect(buttonBox).not.toBeNull();
  expect(buttonBox!.x).toBeGreaterThanOrEqual(0);
  expect(buttonBox!.x + buttonBox!.width).toBeLessThanOrEqual(320);
  await evidenceButton.click();
  const dialogBox = await page.getByRole('dialog', { name: 'Evidence details' }).boundingBox();
  expect(dialogBox).not.toBeNull();
  expect(dialogBox!.x).toBeGreaterThanOrEqual(0);
  expect(dialogBox!.x + dialogBox!.width).toBeLessThanOrEqual(320);

  const contrast = await page.evaluate(() => {
    const channel = (value: number) => {
      const normalized = value / 255;
      return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
    };
    const luminance = (css: string) => {
      const values = css.match(/[\d.]+/g)?.slice(0, 3).map(Number) ?? [0, 0, 0];
      return 0.2126 * channel(values[0]) + 0.7152 * channel(values[1]) + 0.0722 * channel(values[2]);
    };
    const ratio = (foreground: Element, background: Element) => {
      const foregroundLuminance = luminance(getComputedStyle(foreground).color);
      const backgroundLuminance = luminance(getComputedStyle(background).backgroundColor);
      const lighter = Math.max(foregroundLuminance, backgroundLuminance);
      const darker = Math.min(foregroundLuminance, backgroundLuminance);
      return (lighter + 0.05) / (darker + 0.05);
    };
    const samples: Array<[string, string]> = [
      ['.trace-hop-time', '.trace-timeline > li'],
      ['.trace-facts dt', '.trace-facts > div'],
      ['.trace-affected-item span', '.trace-affected-item'],
      ['.trace-scope-line', '.trace-summary-card'],
      ['.navitem:not(.active) .navitem-hint', '.sidenav'],
    ];
    return samples.map(([foreground, background]) => ({
      foreground,
      ratio: ratio(document.querySelector(foreground)!, document.querySelector(background)!),
    }));
  });
  for (const sample of contrast) expect(sample.ratio, sample.foreground).toBeGreaterThanOrEqual(4.5);
});
