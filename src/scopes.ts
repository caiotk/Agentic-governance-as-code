/**
 * Scope matching honours what the manifest grants — including wildcards, so a
 * wildcard grant really is standing privilege at runtime. The static gate
 * rejects wildcards (C3.4); the scope-escalation probe shows why.
 */
export function scopeGranted(granted: string[], needed: string): boolean {
  return granted.some((g) => g === needed || g === '*' || (g.endsWith(':*') && needed.startsWith(g.slice(0, -1))));
}
