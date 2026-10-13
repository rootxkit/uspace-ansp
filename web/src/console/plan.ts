// The plan form's shape and the body it becomes (api/openapi.yaml
// RestrictionCreate). Shape only: the API judges the meaning.
import { z } from "zod";
import { shapes } from "@rootxkit/uspace-ui/form";
import type { DrawOutline, FieldError } from "@rootxkit/uspace-ui/model";
import type { components } from "../api/types";
import { pointOf, polygonOf } from "./draft";
import { positionOf, verticesOfOutline } from "./outline";

type ApiRestrictionCreate = components["schemas"]["RestrictionCreate"];

export const VERTICAL_REFS = ["AMSL", "WGS84"] as const;
export const ZONE_TYPES = ["PROHIBITED", "REQ_AUTHORIZATION"] as const;

/** The form's shape (api/openapi.yaml RestrictionCreate members); meaning is the API's. */
export const planSchema = z.object({
  uspace_airspace_id: z.string().trim().min(1).max(7),
  zone_type: z.enum(ZONE_TYPES),
  lower_m: z.number(),
  lower_ref: z.enum(VERTICAL_REFS),
  upper_m: z.number(),
  upper_ref: z.enum(VERTICAL_REFS),
  starts_at: shapes.utcTime(),
  ends_at: shapes.utcTime(),
  reason_text: z.string().trim().min(1).max(500),
  confirm_chain: z.boolean(),
});

export type PlanValues = z.output<typeof planSchema>;

/**
 * The RestrictionCreate body of the form's values and the drawn outline
 * (the kit's DrawOutline), or the field errors that keep it from being
 * sent (the outline is not a form field, so its shape errors are named
 * here, on `geometry` and `radius_m`). A circle is sent as its centre and
 * radius, never as the outline the API drew for the map.
 */
export function planBody(
  values: PlanValues,
  outline: DrawOutline,
  reasons: { polygon: string; centre: string; radius: string },
): { body: ApiRestrictionCreate } | { errors: FieldError[] } {
  const common = {
    uspace_airspace_id: values.uspace_airspace_id,
    zone_type: values.zone_type,
    lower_m: values.lower_m,
    lower_ref: values.lower_ref,
    upper_m: values.upper_m,
    upper_ref: values.upper_ref,
    starts_at: values.starts_at,
    ends_at: values.ends_at,
    reason_text: values.reason_text,
    ...(values.confirm_chain ? { confirm_chain: true } : {}),
  };
  if (outline.kind === "polygon") {
    const geometry = polygonOf(verticesOfOutline(outline));
    if (geometry === null) return { errors: [{ field: "geometry", reason: reasons.polygon }] };
    return { body: { ...common, geometry, radius_m: null } };
  }
  const errors: FieldError[] = [];
  if (outline.center === null) errors.push({ field: "geometry", reason: reasons.centre });
  if (outline.radiusM === null) errors.push({ field: "radius_m", reason: reasons.radius });
  if (outline.center === null || outline.radiusM === null) return { errors };
  return { body: { ...common, geometry: pointOf(positionOf(outline.center)), radius_m: outline.radiusM } };
}
