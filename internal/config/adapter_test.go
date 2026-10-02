package config

import (
	"slices"
	"testing"
)

func adapterEnv(kv map[string]string) []string {
	base := map[string]string{
		"ANSP_PROCESS": ProcessMannedAdapter, "ANSP_ADAPTER_KIND": "dump1090_sbs", "ANSP_ADAPTER_ID": "adsb-tbs",
		"ANSP_ADAPTER_SOURCE_CLASS": "ads_b", "ANSP_ADAPTER_SBS_ADDR": "dump1090:30003",
	}
	for k, v := range kv {
		base[k] = v
	}
	return env(base)
}

// The manned-adapter settings load (presence), with their defaults.
func TestLoadAdapter(t *testing.T) {
	c, err := LoadFrom(adapterEnv(map[string]string{"ANSP_ADAPTER_REPLAY_SPEED": "2.5"}), noFiles)
	if err != nil {
		t.Fatal(err)
	}
	if c.AdapterKind != "dump1090_sbs" || c.AdapterID != "adsb-tbs" || c.AdapterSBSTimezone != "UTC" ||
		c.AdapterReplayAllowed != "false" || c.AdapterReplaySpeed != 2.5 || c.AdapterReplayLoop != "false" {
		t.Fatalf("%+v", c)
	}
	if r := c.Redacted(); r["ANSP_ADAPTER_REPLAY_SPEED"] != "2.5" {
		t.Fatal(r["ANSP_ADAPTER_REPLAY_SPEED"])
	}
	// Another process does not need them.
	if _, err := LoadFrom(env(nil), noFiles); err != nil {
		t.Fatal(err)
	}
}

// Each manned-adapter setting is refused by name (absence twin).
func TestLoadAdapterRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		want []string
	}{
		"kind missing":   {map[string]string{"ANSP_ADAPTER_KIND": ""}, []string{"ANSP_ADAPTER_KIND"}},
		"kind unknown":   {map[string]string{"ANSP_ADAPTER_KIND": "atm_api"}, []string{"ANSP_ADAPTER_KIND", "ANSP_ADAPTER_KIND"}},
		"id upper":       {map[string]string{"ANSP_ADAPTER_ID": "ADSB"}, []string{"ANSP_ADAPTER_ID"}},
		"id missing":     {map[string]string{"ANSP_ADAPTER_ID": ""}, []string{"ANSP_ADAPTER_ID"}},
		"class missing":  {map[string]string{"ANSP_ADAPTER_SOURCE_CLASS": ""}, []string{"ANSP_ADAPTER_SOURCE_CLASS"}},
		"class unknown":  {map[string]string{"ANSP_ADAPTER_SOURCE_CLASS": "radar"}, []string{"ANSP_ADAPTER_SOURCE_CLASS", "ANSP_ADAPTER_SOURCE_CLASS"}},
		"sbs addr":       {map[string]string{"ANSP_ADAPTER_SBS_ADDR": "dump1090"}, []string{"ANSP_ADAPTER_SBS_ADDR"}},
		"sbs zone":       {map[string]string{"ANSP_ADAPTER_SBS_TIMEZONE": "Nowhere/Town"}, []string{"ANSP_ADAPTER_SBS_TIMEZONE"}},
		"json url":       {map[string]string{"ANSP_ADAPTER_KIND": "dump1090_json"}, []string{"ANSP_ADAPTER_JSON_URL"}},
		"json scheme":    {map[string]string{"ANSP_ADAPTER_KIND": "dump1090_json", "ANSP_ADAPTER_JSON_URL": "ftp://x/a.json"}, []string{"ANSP_ADAPTER_JSON_URL"}},
		"replay file":    {map[string]string{"ANSP_ADAPTER_KIND": "replay"}, []string{"ANSP_ADAPTER_REPLAY_FILE"}},
		"allowed word":   {map[string]string{"ANSP_ADAPTER_REPLAY_ALLOWED": "yes"}, []string{"ANSP_ADAPTER_REPLAY_ALLOWED"}},
		"speed word":     {map[string]string{"ANSP_ADAPTER_REPLAY_SPEED": "fast"}, []string{"ANSP_ADAPTER_REPLAY_SPEED"}},
		"speed too high": {map[string]string{"ANSP_ADAPTER_REPLAY_SPEED": "1001"}, []string{"ANSP_ADAPTER_REPLAY_SPEED"}},
		"speed nan":      {map[string]string{"ANSP_ADAPTER_REPLAY_SPEED": "NaN"}, []string{"ANSP_ADAPTER_REPLAY_SPEED"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFrom(adapterEnv(tc.env), noFiles)
			if got := fieldNames(err); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}
