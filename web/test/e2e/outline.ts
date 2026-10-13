// The editor's outline typed through the kit's OutlineFields (the
// keyboard path beside the map's DrawLayer), as a supervisor would.
import { expect, type Page } from "@playwright/test";

/** Types each [lng, lat] as a new point and adds it. */
export async function typeVertices(page: Page, vertices: readonly (readonly [number, number])[]): Promise<void> {
  for (const [i, [lng, lat]] of vertices.entries()) {
    const n = i + 1;
    await page.getByLabel(`New point ${n}: latitude (degrees, WGS84)`, { exact: true }).fill(String(lat));
    await page.getByLabel(`New point ${n}: longitude (degrees, WGS84)`, { exact: true }).fill(String(lng));
    await page.getByRole("button", { name: "Add point" }).click();
    await expect(page.getByLabel(`Point ${n}: latitude (degrees, WGS84)`, { exact: true })).toHaveValue(String(lat));
  }
}

/** Chooses a circle and types its centre and radius. */
export async function typeCircle(page: Page, centre: readonly [number, number], radiusM: number): Promise<void> {
  await page.getByRole("radio", { name: "Circle" }).check();
  await page.getByLabel("Centre: latitude (degrees, WGS84)", { exact: true }).fill(String(centre[1]));
  await page.getByLabel("Centre: longitude (degrees, WGS84)", { exact: true }).fill(String(centre[0]));
  await page.getByLabel("Radius (m)", { exact: true }).fill(String(radiusM));
}
