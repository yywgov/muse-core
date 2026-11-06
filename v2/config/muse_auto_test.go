package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMuseAutoTagsFilter(t *testing.T) {
	tags := []string{"🇭🇰 香港 01", "🇯🇵 日本 01", "HK-02", "美国 01"}
	require.Equal(t, tags, museAutoTags(tags, ""), "empty = every node")
	require.Equal(t, []string{"🇭🇰 香港 01", "HK-02"}, museAutoTags(tags, `(?i)香港|🇭🇰|\bHK\b|hong ?kong`))
	require.Equal(t, tags, museAutoTags(tags, `新加坡`), "nothing matches = every node, never an empty group")
	require.Equal(t, tags, museAutoTags(tags, `(`), "invalid = every node")
}
