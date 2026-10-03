// The sign-in page's pure parts: the refusals it words itself and the
// path of a QR code's dark modules.

/** The sign-in refusals the console words itself (the API's and the BFF's slugs). */
export const LOGIN_SLUGS = [
  "invalid_credentials",
  "mfa_refused",
  "account_locked",
  "rate_limited",
  "invalid_request",
  "unavailable",
  "mfa_challenge_missing",
  "origin_refused",
  "validation",
  "bff_unavailable",
  "upstream_unreachable",
  "upstream_timeout",
  "upstream_invalid",
] as const;

/** The catalogue key of a refusal: its slug's, else the status's. */
export function refusalKey(slug: string | null, status: number): string {
  if (slug !== null && (LOGIN_SLUGS as readonly string[]).includes(slug)) return `ansp.login.problem.${slug}`;
  return status >= 500 ? "ansp.login.problem.unavailable" : "ansp.login.problem.other";
}

/** The dark modules of a QR code as one SVG path (1 unit per module). */
export function qrPath(data: readonly (readonly boolean[])[]): string {
  const parts: string[] = [];
  data.forEach((row, y) => {
    row.forEach((dark, x) => {
      if (dark) parts.push(`M${x} ${y}h1v1h-1z`);
    });
  });
  return parts.join("");
}
