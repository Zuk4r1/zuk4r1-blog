export function parseDateLocal(dateStr: string): Date {
  const s = (dateStr || '').trim();
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(s);
  if (m) {
    const y = Number(m[1]);
    const mo = Number(m[2]);
    const d = Number(m[3]);
    return new Date(y, mo - 1, d);
  }
  const d = new Date(s);
  return Number.isFinite(d.getTime()) ? d : new Date(0);
}

export function toTimestampLocal(dateStr: string): number {
  const t = parseDateLocal(dateStr).getTime();
  return Number.isFinite(t) ? t : 0;
}

/**
 * Formatea una fecha de post al formato legible en español
 * Consolida la lógica duplicada de formateo en un único lugar
 */
export function formatPostDate(dateStr: string): string {
  return parseDateLocal(dateStr).toLocaleDateString('es-ES', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}
