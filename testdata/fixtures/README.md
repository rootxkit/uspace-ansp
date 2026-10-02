# Fixtures

SYNTHETIC data, never real: the three CIS datasets as the CISP serves
them unfiltered (`GET /v1/{dataset}`, api/clients/cisp.yaml), with the
top-level `cis_dataset`, `cis_version` and `cis_updated_at` members.

- `uspace_airspace.json`: one `USPACE` feature over an invented test
  area with the Art. 3(4) block `extendedProperties.uspace_requirements`
  (`cis/uspace_requirements/v1`).
- `ussp_list.json`: `cis/ussp_list/v1` with two USSPs whose base URLs
  are on `localhost`.
- `restrictions.json`: one `DAR` restriction.

`internal/cis` parses every file in its tests; WP-5, WP-6, WP-8 and
WP-10 read them too. Test keys are generated at run time, never stored.
