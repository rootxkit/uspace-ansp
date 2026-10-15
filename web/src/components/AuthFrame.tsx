"use client";

// The sign-in's frame, in the console's look: the brand and what the
// console is for on one side (wide screens), the form centred on the
// other, the language switch and the scheme toggle above it, the footer
// below. The page's own h1 is the form's.
import type { ReactNode } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { LanguageSwitch } from "@rootxkit/uspace-ui/ui";
import { BrandMark, FrameFooter, SchemeToggle } from "./frame";

export function AuthFrame({ children }: { children: ReactNode }) {
  const t = useT();
  const { brand } = useTheme();
  return (
    <div className="grid min-h-dvh bg-background text-foreground lg:grid-cols-[minmax(0,1fr)_minmax(0,36rem)]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:shadow-overlay"
      >
        {t("ansp.skip")}
      </a>
      <aside className="hidden flex-col justify-between gap-10 border-e border-border bg-sidebar p-10 lg:flex">
        <div className="flex items-center gap-3">
          <span className="inline-flex size-7 items-center justify-center overflow-hidden rounded-md">
            <BrandMark />
          </span>
          <span className="text-sm font-bold">{brand.name}</span>
        </div>
        <div className="flex max-w-lg flex-col gap-4">
          <p className="m-0 text-3xl leading-tight font-bold">{t("ansp.app.title", { name: brand.name })}</p>
          <p className="m-0 text-base text-muted-foreground">{t("ansp.app.tagline")}</p>
          <ul className="m-0 flex list-none flex-col gap-2 p-0 text-sm text-sidebar-text">
            <li className="flex gap-2">
              <span aria-hidden="true" className="mt-1.5 size-1.5 shrink-0 rounded-full bg-brand-accent" />
              {t("ansp.login.point.restrictions")}
            </li>
            <li className="flex gap-2">
              <span aria-hidden="true" className="mt-1.5 size-1.5 shrink-0 rounded-full bg-brand-accent" />
              {t("ansp.login.point.picture")}
            </li>
            <li className="flex gap-2">
              <span aria-hidden="true" className="mt-1.5 size-1.5 shrink-0 rounded-full bg-brand-accent" />
              {t("ansp.login.point.coordination")}
            </li>
          </ul>
        </div>
        <FrameFooter />
      </aside>
      <div className="flex min-w-0 flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-border bg-topbar px-4 py-3 lg:justify-end lg:border-b-0 lg:bg-transparent">
          <span className="flex min-w-0 items-center gap-2.5 lg:hidden">
            <span className="inline-flex size-7 shrink-0 items-center justify-center overflow-hidden rounded-md">
              <BrandMark />
            </span>
            <span className="min-w-0 truncate text-sm font-bold">{brand.name}</span>
          </span>
          <span className="flex items-center gap-2">
            <SchemeToggle />
            <LanguageSwitch />
          </span>
        </header>
        <main id="main" tabIndex={-1} className="flex flex-1 items-center justify-center px-4 py-8 outline-none">
          <div className="w-full max-w-sm">{children}</div>
        </main>
        <div className="px-4 pb-4 lg:hidden">
          <FrameFooter />
        </div>
      </div>
    </div>
  );
}
