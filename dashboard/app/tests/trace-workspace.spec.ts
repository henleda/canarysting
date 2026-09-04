import { expect, test } from '@playwright/test';

const TRACE_ID = `trace:sha256:${'1'.repeat(64)}`;

test('explains a partial, conflicted trace and opens raw evidence in one click', async ({ page }) => {
  await page.goto(`/traces/${TRACE_ID}`);

  await expect(page.getByRole('heading', { level: 1, name: 'Conflicting evidence across Checkout API and Payments' })).toBeVisible();
  await expect(page.getByLabel('Trace status: Conflicted')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What happened' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Why CanaryView believes this' })).toBeVisible();
  await expect(page.getByText('Partial coverage', { exact: true })).toBeVisible();
  await expect(page.getByText('Conflicting evidence', { exact: true })).toBeVisible();
  await expect(page.getByText('This workspace is read-only and cannot trigger or change a response.')).toBeVisible();

  const evidenceButton = page.getByRole('button', { name: 'View raw evidence for Gateway request' });
  await expect(evidenceButton).toBeVisible();
  await evidenceButton.click();

  const drawer = page.getByRole('dialog', { name: 'Evidence details' });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText('Integrity mismatch', { exact: true })).toBeVisible();
  await expect(drawer.getByText('Source-owned reference', { exact: true })).toBeVisible();
  await expect(drawer.getByText('No source payload is stored in this workspace.')).toBeVisible();

  await page.keyboard.press('Escape');
  await expect(drawer).not.toBeVisible();
  await expect(evidenceButton).toBeFocused();
});

test('supports the evidence path from the keyboard', async ({ page }) => {
  await page.goto(`/traces/${TRACE_ID}`);

  const evidenceButton = page.getByRole('button', { name: 'View raw evidence for Gateway request' });
  await evidenceButton.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog', { name: 'Evidence details' })).toBeVisible();
});
