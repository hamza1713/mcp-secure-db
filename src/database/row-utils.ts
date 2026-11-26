/**
 * Disambiguates duplicate SQL result column names (e.g. `SELECT c.id, u.id ...`)
 * so row objects never silently overwrite earlier columns.
 *
 * Example: ["id", "name", "id", "id"] -> ["id", "name", "id_2", "id_3"]
 */
export function disambiguateColumnNames(rawColumns: readonly string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];

  for (let i = 0; i < rawColumns.length; i++) {
    const base = rawColumns[i] || `col_${i + 1}`;
    if (!seen.has(base)) {
      seen.add(base);
      result.push(base);
      continue;
    }

    let suffix = 2;
    let candidate = `${base}_${suffix}`;
    while (seen.has(candidate)) {
      suffix += 1;
      candidate = `${base}_${suffix}`;
    }
    seen.add(candidate);
    result.push(candidate);
  }

  return result;
}
