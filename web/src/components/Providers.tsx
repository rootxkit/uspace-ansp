"use client";

import { createContext, useCallback, useContext, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { I18nProvider, LANG_COOKIE, type Lang } from "@rootxkit/uspace-ui/i18n";
import { SCHEME_COOKIE, ThemeProvider, type Brand, type ColorScheme } from "@rootxkit/uspace-ui/theme";
import { CspNonceProvider } from "@rootxkit/uspace-ui/ui";
import { catalogues } from "../i18n/catalogues";
import type { RuntimeConfig } from "../runtime";

const RuntimeContext = createContext<RuntimeConfig | null>(null);

/** The request-time configuration the server handed to the page. */
export function useRuntimeConfig(): RuntimeConfig {
  const v = useContext(RuntimeContext);
  if (v === null) throw new Error("useRuntimeConfig outside Providers");
  return v;
}

/** A display preference kept for a year, readable by the server's next render. */
function remember(name: string, value: string): void {
  document.cookie = `${name}=${value}; Path=/; Max-Age=31536000; SameSite=Lax`;
}

/** The same path in another language: the locale is the path's first segment. */
export function pathIn(pathname: string, l: Lang): string {
  return `/${l}${pathname.replace(/^\/(ka|en)(?=\/|$)/, "")}`;
}

export function Providers(props: {
  lang: Lang;
  brand: Brand;
  nonce: string | undefined;
  config: RuntimeConfig;
  /** The uspace_scheme cookie's choice; absent follows the system. */
  scheme: ColorScheme | null;
  children: ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  // The language is the URL's: the kit's switch asks, the page moves to
  // the same path in the other language and remembers it in uspace_lang.
  const onLangChange = useCallback(
    (l: Lang) => {
      remember(LANG_COOKIE, l);
      router.push(`${pathIn(pathname, l)}${window.location.search}`);
    },
    [router, pathname],
  );
  const onSchemeChange = useCallback((s: ColorScheme) => remember(SCHEME_COOKIE, s), []);
  return (
    <CspNonceProvider nonce={props.nonce}>
      <RuntimeContext.Provider value={props.config}>
        <ThemeProvider brand={props.brand} {...(props.scheme === null ? {} : { scheme: props.scheme })} onSchemeChange={onSchemeChange}>
          <I18nProvider lang={props.lang} catalogues={catalogues} onLangChange={onLangChange}>
            {props.children}
          </I18nProvider>
        </ThemeProvider>
      </RuntimeContext.Provider>
    </CspNonceProvider>
  );
}
