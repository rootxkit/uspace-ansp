import type { ReactNode } from "react";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { readSessionToken, sessionDisplay } from "@rootxkit/uspace-ui/auth/server";
import { ConsoleShell } from "@/src/console/ConsoleShell";

// Every signed-in page: the status bar, the navigation and the account
// (src/console/ConsoleShell). The session claims are read from the
// cookie without verification, for display only (the kit's
// sessionClaimsUnverified: sub, roles[], realm, exp; M20); without a
// session cookie the page is the sign-in. The API decides every request.
export default async function SignedInLayout({
  children,
  params,
}: {
  children: ReactNode;
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const session = sessionDisplay(readSessionToken(await cookies()));
  if (session === null) redirect(`/${locale}/login`);
  return <ConsoleShell session={session}>{children}</ConsoleShell>;
}
