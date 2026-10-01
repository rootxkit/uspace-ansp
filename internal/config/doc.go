// Package config loads the ANSP_* environment of a process into one
// Config (docs/PLAN.md sections 8 and 11). Every problem is reported at
// once, each as a *core.FieldError naming the variable; an ANSP_*
// variable that is not in the catalogue is refused, so a typo never
// silently leaves the real variable at its default. Secrets are read
// from files (*_FILE), never from the environment, and Redacted is the
// only form of the configuration that is logged.
package config
