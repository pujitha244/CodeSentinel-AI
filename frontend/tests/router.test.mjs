import assert from 'node:assert/strict';
import test from 'node:test';
import { matchRoutes } from 'react-router-dom';

const appRoutes = [
  { path: '/', id: 'overview' },
  { path: '/dashboard', id: 'dashboard' },
  { path: '/chains', id: 'chains' },
  { path: '/remediation', id: 'remediation' },
  { path: '/reports', id: 'reports' },
];

test('React Router resolves the primary application routes', () => {
  for (const [path, routeId] of [
    ['/', 'overview'],
    ['/dashboard', 'dashboard'],
    ['/chains', 'chains'],
    ['/remediation', 'remediation'],
    ['/reports', 'reports'],
  ]) {
    assert.equal(matchRoutes(appRoutes, path)?.at(-1)?.route.id, routeId);
  }
});

test('React Router keeps route parameters available to dynamic routes', () => {
  const matches = matchRoutes([{ path: '/reports/:auditId', id: 'report' }], '/reports/audit-demo');
  assert.equal(matches?.at(-1)?.params.auditId, 'audit-demo');
});
