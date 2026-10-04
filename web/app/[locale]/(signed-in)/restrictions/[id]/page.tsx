import { RestrictionDetailPage } from "@/src/console/RestrictionDetailPage";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <RestrictionDetailPage id={id} />;
}
