/**
 * Detect the web path prefix from the current URL.
 * E.g. if the user is at http://host:port/abc123/dashboard, returns "/abc123".
 * Returns "" if no prefix detected.
 */
export function getBasePath(): string {
  if (typeof window === 'undefined') return '';
  const parts = window.location.pathname.split('/').filter(Boolean);
  // First segment is the random web path, unless it's a known page route
  const knownRoots = ['dashboard', 'login', '_next', 'api'];
  if (parts.length > 0 && !knownRoots.includes(parts[0])) {
    return '/' + parts[0];
  }
  return '';
}
