package config

// 穿云 1.12.0 - 自动最快 limited to one region: the app sends a pattern (muse-auto-filter) built
// from the region's names and flags; the lowest-delay group then only holds the nodes whose tag
// matches. The group itself (type, tolerance, how it tests) is unchanged, and an empty, invalid or
// unmatched pattern keeps every node, so the connection never ends up with an empty group.

import "regexp"

func museAutoTags(tags []string, filter string) []string {
	if filter == "" {
		return tags
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		return tags
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if re.MatchString(t) {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return tags
	}
	return out
}
