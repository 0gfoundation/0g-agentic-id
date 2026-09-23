package hermes

import "seal-verify/internal/studio"

func (a *Adapter) StudioLayout() studio.Layout {
	return studio.Layout{Resources: []studio.Resource{
		{Kind: studio.KindPersonality, Format: "markdown", Activation: studio.ActivationNextSession, Role: "SOUL.md", Mode: studio.ModeSingleton, Root: soulMDPath(), SingletonID: "main", StripInjected: true},
		{Kind: studio.KindSkills, Format: "skill_bundle", Activation: studio.ActivationRestartRequired, Role: "skills/", Mode: studio.ModeBundles, Root: skillsDir(), Required: []string{"SKILL.md"}, RejectIDs: bundledSkillSlugs},
		{Kind: studio.KindMemory, Format: "markdown", Activation: studio.ActivationNextSession, Role: "memories/", Mode: studio.ModeMarkdown, Root: memoriesDir()},
	}}
}

var _ studio.Provider = (*Adapter)(nil)
