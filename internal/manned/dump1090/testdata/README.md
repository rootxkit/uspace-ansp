# dump1090 samples (synthetic)

These samples are synthetic: no line or document here was captured from a
real receiver, and every ICAO address (`f0a001` ...) and callsign is made
up. dump1090's repository publishes no example output, and no dump1090
run was available to capture one, so each sample was written by applying
the pinned writer's format strings (`SOURCE`) to made-up values:

- `sbs-from-writer-format.txt`: `modesSendSBSOutput` in `net_io.c`
  (lines 571-787), 22 columns, CRLF line endings, with the empty
  heartbeat line of `send_sbs_heartbeat`. The second position line uses
  the `H` suffix the writer adds with `--gnss`.
- `aircraft-from-writer-format.json`: `generateAircraftJson` in
  `net_io.c` (lines 1732-1870), keys and order as written there, values
  in the units README-json.md gives.

The golden tests derive their expected values from README-json.md's
field definitions and the writer's column comments, cited in each test.
A capture from a real dump1090 run should replace these when one is
available (docs/PLAN.md section 15 gap 27).
