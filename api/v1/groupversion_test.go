package v1

import "testing"

// One binary, any universe. The group was a compile-time constant, so a Lux
// install could not be served without a rebuild.
func TestSetGroupFollowsTheUniverse(t *testing.T) {
	orig := GroupVersion
	defer func() { GroupVersion = orig; SchemeBuilder.GroupVersion = orig }()

	if GroupVersion.Group != DefaultGroup || GroupVersion.Version != Version {
		t.Fatalf("default is %s, want %s/%s", GroupVersion, DefaultGroup, Version)
	}
	for _, g := range []string{"kms.hanzo.ai", "kms.lux.cloud", "kms.zoo.cloud"} {
		SetGroup(g)
		if GroupVersion.Group != g {
			t.Errorf("SetGroup(%q) left the group at %q", g, GroupVersion.Group)
		}
		if GroupVersion.Version != Version {
			t.Errorf("SetGroup(%q) changed the version to %q", g, GroupVersion.Version)
		}
	}
}

// The SchemeBuilder captures its GroupVersion when the types register, so a
// SetGroup that did not carry through would leave the scheme on one group while
// the manager watched another. That controller starts clean, logs nothing and
// never sees an object — which reads as "no work to do" rather than as a
// misconfiguration, and is why the ordering is asserted rather than remembered.
func TestSetGroupCarriesThroughToTheSchemeBuilder(t *testing.T) {
	orig := GroupVersion
	defer func() { GroupVersion = orig; SchemeBuilder.GroupVersion = orig }()

	SetGroup("kms.lux.cloud")
	if SchemeBuilder.GroupVersion != GroupVersion {
		t.Errorf("builder on %s, group on %s", SchemeBuilder.GroupVersion, GroupVersion)
	}
}

// An empty flag means unset, not the empty group: a scheme registered under ""
// matches nothing.
func TestAnEmptyGroupIsIgnored(t *testing.T) {
	orig := GroupVersion
	defer func() { GroupVersion = orig; SchemeBuilder.GroupVersion = orig }()

	SetGroup("kms.lux.cloud")
	SetGroup("")
	if GroupVersion.Group != "kms.lux.cloud" {
		t.Errorf("an empty SetGroup changed the group to %q", GroupVersion.Group)
	}
}
