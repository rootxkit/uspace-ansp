import { Suspense } from "react";
import { RequestsPage } from "@/src/console/RequestsPage";

// The request id is a search parameter (useSearchParams), read under Suspense.
export default function Page() {
  return (
    <Suspense>
      <RequestsPage />
    </Suspense>
  );
}
