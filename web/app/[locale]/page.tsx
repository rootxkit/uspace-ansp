import { redirect } from "next/navigation";

// The console's first page is the restrictions list.
export default async function Home({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  redirect(`/${locale}/restrictions`);
}
