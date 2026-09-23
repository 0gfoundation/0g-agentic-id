package prime

import "seal-verify/internal/studio"

func (a *Adapter) StudioLayout() studio.Layout {
	return studio.Layout{Resources: []studio.Resource{
		{Kind: studio.KindPersonality, Format: "markdown", Activation: studio.ActivationNextSession, Role: "APPEND_SYSTEM.md", Mode: studio.ModeSingleton, Root: appendSystemPath(), SingletonID: "main"},
		{Kind: studio.KindSkills, Format: "python_skill_bundle", Activation: studio.ActivationNextSession, Role: "skills/", Mode: studio.ModeBundles, Root: skillsDir(), Required: []string{"SKILL.md", "pyproject.toml"}, RequirePrefix: []string{"src/"}},
	}}
}

var _ studio.Provider = (*Adapter)(nil)
