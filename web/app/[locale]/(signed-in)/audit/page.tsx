import { Suspense } from "react";
import { AuditPage } from "@/src/console/AuditPage";

// The entity to list is a search parameter (useSearchParams), read under Suspense.
export default function Page() {
  return (
    <Suspense>
      <AuditPage />
    </Suspense>
  );
}
