package openclaw

import "seal-verify/internal/studio"

func (a *Adapter) StudioLayout() studio.Layout {
	return studio.Layout{Resources: []studio.Resource{
		{Kind: studio.KindPersonality, Format: "markdown", Activation: studio.ActivationActive, Role: "workspace/", Mode: studio.ModeSingleton, Root: soulMDPath(), SingletonID: "main", StripInjected: true},
		{Kind: studio.KindSkills, Format: "skill_bundle", Activation: studio.ActivationActive, Role: "workspace/skills/", Mode: studio.ModeBundles, Root: workspaceDir() + "/skills", Required: []string{"SKILL.md"}},
		{Kind: studio.KindMemory, Format: "markdown", Activation: studio.ActivationActive, Role: "workspace/", Mode: studio.ModeSingleton, Root: memoryMDPath(), SingletonID: "main"},
		{Kind: studio.KindFiles, Format: "text_file", Activation: studio.ActivationActive, Role: "workspace/canvas/", Mode: studio.ModeFiles, Root: workspaceDir() + "/canvas"},
	}}
}

var _ studio.Provider = (*Adapter)(nil)
