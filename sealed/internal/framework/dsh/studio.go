package dsh

import "seal-verify/internal/studio"

func (a *Adapter) StudioLayout() studio.Layout {
	return studio.Layout{Resources: []studio.Resource{
		{Kind: studio.KindPersonality, Format: "markdown", Activation: studio.ActivationActive, Role: "APPEND_SYSTEM.md", Mode: studio.ModeSingleton, Root: appendSystemPath(), SingletonID: "main"},
		{Kind: studio.KindSkills, Format: "skill_bundle", Activation: studio.ActivationRestartRequired, Role: "skills/", Mode: studio.ModeBundles, Root: skillsDir(), Required: []string{"SKILL.md"}},
	}}
}

var _ studio.Provider = (*Adapter)(nil)
