package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KMSPushSecretDestination struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Immutable
	SecretsPath string `json:"secretsPath"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Immutable
	EnvironmentSlug string `json:"environmentSlug"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Immutable
	ProjectID string `json:"projectId"`
}

type KMSPushSecretSecretSource struct {
	// The name of the Kubernetes Secret
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName"`

	// The name space where the Kubernetes Secret is located
	// +kubebuilder:validation:Required
	SecretNamespace string `json:"secretNamespace"`

	// +kubebuilder:validation:Optional
	Template *SecretTemplate `json:"template,omitempty"`
}

type GeneratorRef struct {
	// Specify the Kind of the generator resource
	// +kubebuilder:validation:Enum=Password;UUID
	// +kubebuilder:validation:Required
	Kind GeneratorKind `json:"kind"`

	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type SecretPushGenerator struct {
	// +kubebuilder:validation:Required
	DestinationSecretName string `json:"destinationSecretName"`
	// +kubebuilder:validation:Required
	GeneratorRef GeneratorRef `json:"generatorRef"`
}

type SecretPush struct {
	// +kubebuilder:validation:Optional
	Secret *KMSPushSecretSecretSource `json:"secret,omitempty"`
	// +kubebuilder:validation:Optional
	Generators []SecretPushGenerator `json:"generators,omitempty"`
}

// KMSPushSecretSpec defines the desired state of KMSPushSecret
type KMSPushSecretSpec struct {
	// +kubebuilder:validation:Optional
	UpdatePolicy string `json:"updatePolicy"`

	// +kubebuilder:validation:Optional
	DeletionPolicy string `json:"deletionPolicy"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Immutable
	Destination KMSPushSecretDestination `json:"destination"`

	// +kubebuilder:validation:Optional
	Authentication GenericKMSAuthentication `json:"authentication"`

	// +kubebuilder:validation:Required
	Push SecretPush `json:"push"`

	// +kubebuilder:validation:Optional
	ResyncInterval *string `json:"resyncInterval,omitempty"`

	// KMS host to pull secrets from
	// +kubebuilder:validation:Optional
	HostAPI string `json:"hostAPI"`

	// +kubebuilder:validation:Optional
	TLS TLSConfig `json:"tls"`
}

// KMSPushSecretStatus defines the observed state of KMSPushSecret
type KMSPushSecretStatus struct {
	Conditions []metav1.Condition `json:"conditions"`

	// managed secrets is a map where the key is the ID, and the value is the secret key (string[id], string[key] )
	ManagedSecrets map[string]string `json:"managedSecrets"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// KMSPushSecret is the Schema for the kmspushsecrets API
type KMSPushSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KMSPushSecretSpec   `json:"spec,omitempty"`
	Status KMSPushSecretStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KMSPushSecretList contains a list of KMSPushSecret
type KMSPushSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KMSPushSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KMSPushSecret{}, &KMSPushSecretList{})
}
