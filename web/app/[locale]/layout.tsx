import type { Metadata } from "next";
import type { ReactNode } from "react";
import { cookies, headers } from "next/headers";
import { notFound } from "next/navigation";
import { CSP_NONCE_HEADER } from "@rootxkit/uspace-ui/auth/server";
import { fontClassName } from "@rootxkit/uspace-ui/fonts";
import { createTranslator } from "@rootxkit/uspace-ui/i18n";
import { SCHEME_COOKIE, parseScheme, schemeAttribute } from "@rootxkit/uspace-ui/theme";
import { Providers } from "@/src/components/Providers";
import { branding } from "@/src/branding";
import { catalogues, isLang } from "@/src/i18n/catalogues";
import { runtimeConfig } from "@/src/runtime";
import "../globals.css";

export const dynamic = "force-dynamic";

/** The document's title in the page's language: the console's name, the brand being configuration. */
export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  if (!isLang(locale)) return {};
  return { title: createTranslator(locale, catalogues)("ansp.app.title", { name: branding().name }) };
}

// The frame is the page's: the signed-in console sits in the kit's
// AppShell (src/console/ConsoleShell), the sign-in in its own centred
// frame (src/components/AuthFrame).
export default async function LocaleLayout({
  children,
  params,
}: {
  children: ReactNode;
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  if (!isLang(locale)) notFound();
  const nonce = (await headers()).get(CSP_NONCE_HEADER) ?? undefined;
  const brand = branding();
  // An explicit scheme is painted from the first byte; none follows the
  // system preference until ThemeProvider sets it.
  const scheme = parseScheme((await cookies()).get(SCHEME_COOKIE)?.value);
  return (
    <html lang={locale} className={fontClassName} data-theme={schemeAttribute(scheme)} suppressHydrationWarning>
      <body className="font-sans antialiased">
        <Providers lang={locale} brand={brand} nonce={nonce} config={runtimeConfig()} scheme={scheme}>
          {children}
        </Providers>
      </body>
    </html>
  );
}
