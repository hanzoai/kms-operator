// Package v1 contains API Schema definitions for the KMSSecret API group.
//
// The group is kms.<universe> — kms.hanzo.ai on a Hanzo install, kms.lux.cloud
// on a Lux one. It was a compile-time constant, so one binary could serve only
// one of them; SetGroup makes it an argument, the way hanzoai/operator and
// luxfi/operator already take theirs.
//
// Call SetGroup BEFORE AddToScheme. The SchemeBuilder captures its GroupVersion
// when the types register, so setting the group afterwards leaves the scheme on
// one group while the manager watches another — a controller that starts clean,
// logs nothing, and never sees an object.
//
// +kubebuilder:object:generate=true
// +groupName=kms.hanzo.ai
package v1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// DefaultGroup is the group served when nothing overrides it.
const DefaultGroup = "kms.hanzo.ai"

// Version is the served version.
const Version = "v1"

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: DefaultGroup, Version: Version}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// SetGroup points this operator at one universe's KMS group. Call it before
// AddToScheme; afterwards the scheme has already captured the old value.
func SetGroup(group string) {
	if group == "" {
		return
	}
	GroupVersion = schema.GroupVersion{Group: group, Version: Version}
	SchemeBuilder.GroupVersion = GroupVersion
	AddToScheme = SchemeBuilder.AddToScheme
}
