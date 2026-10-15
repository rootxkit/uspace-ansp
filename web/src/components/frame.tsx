"use client";

// The parts both frames share, the signed-in AppShell and the sign-in:
// the brand's mark, the light/dark toggle and the footer that says who
// runs the console and what it never does. The brand is configuration
// (WEB_BRANDING_FILE); nothing here is an organisation's.
import { useT } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { Mark, MoonIcon, SunIcon } from "./icons";

/** The brand's logo when one is configured, else a neutral mark. Decorative: the name is beside it. */
export function BrandMark() {
  const { brand } = useTheme();
  if (brand.logoUrl !== null) return <img src={brand.logoUrl} alt="" className="size-7 object-contain" />;
  return <Mark />;
}

/** Light or dark, remembered in uspace_scheme (a display preference). */
export function SchemeToggle() {
  const t = useT();
  const { resolved, setScheme } = useTheme();
  const dark = resolved === "dark";
  return (
    <button
      type="button"
      aria-pressed={dark}
      aria-label={t("ansp.scheme.dark")}
      data-testid="scheme-toggle"
      onClick={() => setScheme(dark ? "light" : "dark")}
      className="inline-flex size-8 shrink-0 items-center justify-center rounded-md border border-border bg-card text-foreground transition-colors hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
    >
      {dark ? <MoonIcon /> : <SunIcon />}
    </button>
  );
}

/** Who operates the console, how to reach them, and that it never commands an aircraft. */
export function FrameFooter({ scope = false }: { scope?: boolean }) {
  const t = useT();
  const { brand } = useTheme();
  return (
    <footer className="flex flex-col gap-1 border-t border-border pt-3 text-xs text-muted-foreground">
      {scope && <p className="m-0 max-w-prose">{t("ansp.scope_notice")}</p>}
      <p className="m-0 flex flex-wrap gap-x-4 gap-y-1">
        <span>{t("ansp.footer.operator", { name: brand.name })}</span>
        {brand.contact !== null && <span>{t("ansp.footer.contact", { contact: brand.contact })}</span>}
        <span className="font-semibold">{t("ansp.footer.no_command")}</span>
      </p>
    </footer>
  );
}
