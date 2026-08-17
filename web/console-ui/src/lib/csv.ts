// CSV writing for the console's exports.
//
// There is no export endpoint. Every export is the same page walk the pickers
// already do, under the same declared bound, with the file assembled here — so
// the rows in the file are the rows the API answered under the filters the
// operator is looking at, and a bounded walk can say so.

/**
 * Renders one CSV field.
 *
 * Every field is quoted and embedded quotes are doubled, so a display name with
 * a comma cannot shift the columns. A leading `=`, `+`, `-`, or `@` is prefixed
 * with an apostrophe: a spreadsheet reads those as a formula, which turns an
 * attacker-chosen username into code running on whoever opens the export.
 */
export function csvCell(v: string): string {
  const s = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
  return `"${s.replace(/"/g, '""')}"`;
}

/** Writes the file from the browser, BOM-first so Excel reads it as UTF-8. */
export function downloadCsv(filename: string, body: string) {
  const url = URL.createObjectURL(new Blob([`﻿${body}`], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
