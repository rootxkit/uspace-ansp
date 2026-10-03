"use client";

import type { ReactNode } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { LocaleSwitch } from "./LocaleSwitch";

/** Header and footer around every page; the brand is configuration (WEB_BRANDING_FILE). */
export function Shell({ children }: { children: ReactNode }) {
  const t = useT();
  const { brand } = useTheme();
  return (
    <div className="flex min-h-full flex-col">
      <a href="#main" className="sr-only focus:not-sr-only">
        {t("ansp.skip")}
      </a>
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--us-border)] bg-[var(--us-surface-raised)] px-4 py-3">
        <div className="flex items-center gap-3">
          {brand.logoUrl !== null && <img src={brand.logoUrl} alt="" className="h-8 w-auto" />}
          <div>
            <h1 className="m-0 text-lg font-bold">{t("ansp.app.title", { name: brand.name })}</h1>
            <p className="m-0 text-sm text-[var(--us-text-muted)]">{t("ansp.app.tagline")}</p>
          </div>
        </div>
        <LocaleSwitch />
      </header>
      <main id="main" className="flex-1">
        {children}
      </main>
      <footer className="border-t border-[var(--us-border)] px-4 py-2 text-xs text-[var(--us-text-muted)]">
        <span>{t("ansp.footer.operator", { name: brand.name })}</span>
        {brand.contact !== null && <span className="ms-4">{t("ansp.footer.contact", { contact: brand.contact })}</span>}
        <span className="ms-4">{t("ansp.footer.no_command")}</span>
      </footer>
    </div>
  );
}
