package util

import (
	"context"
	"fmt"

	"errors"

	corev1 "k8s.io/api/core/v1"

	authenticationv1 "k8s.io/api/authentication/v1"

	"github.com/luxfi/kms/k8-operator/api/v1alpha1"
	"github.com/aws/smithy-go/ptr"
	kmsSdk "github.com/luxfi/kms-go"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetServiceAccountToken(k8sClient client.Client, namespace string, serviceAccountName string, autoCreateServiceAccountToken bool, serviceAccountTokenAudiences []string) (string, error) {

	if autoCreateServiceAccountToken {
		restClient, err := GetRestClientFromClient()
		if err != nil {
			return "", fmt.Errorf("failed to get REST client: %w", err)
		}

		tokenRequest := &authenticationv1.TokenRequest{
			Spec: authenticationv1.TokenRequestSpec{
				ExpirationSeconds: ptr.Int64(600), // 10 minutes. the token only needs to be valid for when we do the initial k8s login.
			},
		}

		if len(serviceAccountTokenAudiences) > 0 {
			// Conditionally add the audiences if they are specified.
			// Failing to do this causes a default audience to be used, which is not what we want if the user doesn't specify any.
			tokenRequest.Spec.Audiences = serviceAccountTokenAudiences
		}

		result := &authenticationv1.TokenRequest{}
		err = restClient.
			Post().
			Namespace(namespace).
			Resource("serviceaccounts").
			Name(serviceAccountName).
			SubResource("token").
			Body(tokenRequest).
			Do(context.Background()).
			Into(result)

		if err != nil {
			return "", fmt.Errorf("failed to create token: %w", err)
		}

		return result.Status.Token, nil
	}

	serviceAccount := &corev1.ServiceAccount{}
	err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: serviceAccountName, Namespace: namespace}, serviceAccount)
	if err != nil {
		return "", err
	}

	if len(serviceAccount.Secrets) == 0 {
		return "", fmt.Errorf("no secrets found for service account %s", serviceAccountName)
	}

	secretName := serviceAccount.Secrets[0].Name

	secret := &corev1.Secret{}
	err = k8sClient.Get(context.TODO(), client.ObjectKey{Name: secretName, Namespace: namespace}, secret)
	if err != nil {
		return "", err
	}

	token := secret.Data["token"]

	return string(token), nil
}

type AuthStrategyType string

var AuthStrategy = struct {
	SERVICE_TOKEN                 AuthStrategyType
	SERVICE_ACCOUNT               AuthStrategyType
	UNIVERSAL_MACHINE_IDENTITY    AuthStrategyType
	KUBERNETES_MACHINE_IDENTITY   AuthStrategyType
	AWS_IAM_MACHINE_IDENTITY      AuthStrategyType
	AZURE_MACHINE_IDENTITY        AuthStrategyType
	GCP_ID_TOKEN_MACHINE_IDENTITY AuthStrategyType
	GCP_IAM_MACHINE_IDENTITY      AuthStrategyType
}{
	SERVICE_TOKEN:                 "SERVICE_TOKEN",
	SERVICE_ACCOUNT:               "SERVICE_ACCOUNT",
	UNIVERSAL_MACHINE_IDENTITY:    "UNIVERSAL_MACHINE_IDENTITY",
	KUBERNETES_MACHINE_IDENTITY:   "KUBERNETES_AUTH_MACHINE_IDENTITY",
	AWS_IAM_MACHINE_IDENTITY:      "AWS_IAM_MACHINE_IDENTITY",
	AZURE_MACHINE_IDENTITY:        "AZURE_MACHINE_IDENTITY",
	GCP_ID_TOKEN_MACHINE_IDENTITY: "GCP_ID_TOKEN_MACHINE_IDENTITY",
	GCP_IAM_MACHINE_IDENTITY:      "GCP_IAM_MACHINE_IDENTITY",
}

type SecretCrdType string

var SecretCrd = struct {
	KMS_SECRET         SecretCrdType
	KMS_PUSH_SECRET    SecretCrdType
	KMS_DYNAMIC_SECRET SecretCrdType
}{
	KMS_SECRET:         "KMS_SECRET",
	KMS_PUSH_SECRET:    "KMS_PUSH_SECRET",
	KMS_DYNAMIC_SECRET: "KMS_DYNAMIC_SECRET",
}

type SecretAuthInput struct {
	Secret interface{}
	Type   SecretCrdType
}

type AuthenticationDetails struct {
	AuthStrategy          AuthStrategyType
	MachineIdentityScope  v1alpha1.MachineIdentityScopeInWorkspace // This will only be set if a machine identity auth method is used (e.g. UniversalAuth or KubernetesAuth, etc.)
	IsMachineIdentityAuth bool
	SecretType            SecretCrdType
}

var ErrAuthNotApplicable = errors.New("authentication not applicable")

func HandleUniversalAuth(ctx context.Context, reconcilerClient client.Client, secretCrd SecretAuthInput, kmsClient kmsSdk.KMSClientInterface) (AuthenticationDetails, error) {

	var universalAuthSpec v1alpha1.UniversalAuthDetails

	switch secretCrd.Type {
	case SecretCrd.KMS_SECRET:
		kmsSecret, ok := secretCrd.Secret.(v1alpha1.KMSSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSSecret")
		}
		universalAuthSpec = kmsSecret.Spec.Authentication.UniversalAuth
	case SecretCrd.KMS_PUSH_SECRET:
		kmsPushSecret, ok := secretCrd.Secret.(v1alpha1.KMSPushSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSPushSecret")
		}

		universalAuthSpec = v1alpha1.UniversalAuthDetails{
			CredentialsRef: kmsPushSecret.Spec.Authentication.UniversalAuth.CredentialsRef,
			SecretsScope:   v1alpha1.MachineIdentityScopeInWorkspace{},
		}

	case SecretCrd.KMS_DYNAMIC_SECRET:
		kmsDynamicSecret, ok := secretCrd.Secret.(v1alpha1.KMSDynamicSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSDynamicSecret")
		}

		universalAuthSpec = v1alpha1.UniversalAuthDetails{
			CredentialsRef: kmsDynamicSecret.Spec.Authentication.UniversalAuth.CredentialsRef,
			SecretsScope:   v1alpha1.MachineIdentityScopeInWorkspace{},
		}
	}

	universalAuthKubeSecret, err := GetKMSUniversalAuthFromKubeSecret(ctx, reconcilerClient, v1alpha1.KubeSecretReference{
		SecretNamespace: universalAuthSpec.CredentialsRef.SecretNamespace,
		SecretName:      universalAuthSpec.CredentialsRef.SecretName,
	})

	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("ReconcileKMSSecret: unable to get machine identity creds from kube secret [err=%s]", err)
	}

	if universalAuthKubeSecret.ClientId == "" && universalAuthKubeSecret.ClientSecret == "" {
		return AuthenticationDetails{}, ErrAuthNotApplicable
	}

	_, err = kmsClient.Auth().UniversalAuthLogin(universalAuthKubeSecret.ClientId, universalAuthKubeSecret.ClientSecret)
	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("unable to login with machine identity credentials [err=%s]", err)
	}

	return AuthenticationDetails{
		AuthStrategy:          AuthStrategy.UNIVERSAL_MACHINE_IDENTITY,
		MachineIdentityScope:  universalAuthSpec.SecretsScope,
		IsMachineIdentityAuth: true,
		SecretType:            secretCrd.Type,
	}, nil
}

func HandleKubernetesAuth(ctx context.Context, reconcilerClient client.Client, secretCrd SecretAuthInput, kmsClient kmsSdk.KMSClientInterface) (AuthenticationDetails, error) {
	var kubernetesAuthSpec v1alpha1.KubernetesAuthDetails

	switch secretCrd.Type {
	case SecretCrd.KMS_SECRET:
		kmsSecret, ok := secretCrd.Secret.(v1alpha1.KMSSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSSecret")
		}
		kubernetesAuthSpec = kmsSecret.Spec.Authentication.KubernetesAuth
	case SecretCrd.KMS_PUSH_SECRET:
		kmsPushSecret, ok := secretCrd.Secret.(v1alpha1.KMSPushSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSPushSecret")
		}
		kubernetesAuthSpec = v1alpha1.KubernetesAuthDetails{
			IdentityID: kmsPushSecret.Spec.Authentication.KubernetesAuth.IdentityID,
			ServiceAccountRef: v1alpha1.KubernetesServiceAccountRef{
				Namespace: kmsPushSecret.Spec.Authentication.KubernetesAuth.ServiceAccountRef.Namespace,
				Name:      kmsPushSecret.Spec.Authentication.KubernetesAuth.ServiceAccountRef.Name,
			},
			SecretsScope:                  v1alpha1.MachineIdentityScopeInWorkspace{},
			AutoCreateServiceAccountToken: kmsPushSecret.Spec.Authentication.KubernetesAuth.AutoCreateServiceAccountToken,
			ServiceAccountTokenAudiences:  kmsPushSecret.Spec.Authentication.KubernetesAuth.ServiceAccountTokenAudiences,
		}

	case SecretCrd.KMS_DYNAMIC_SECRET:
		kmsDynamicSecret, ok := secretCrd.Secret.(v1alpha1.KMSDynamicSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSDynamicSecret")
		}

		kubernetesAuthSpec = v1alpha1.KubernetesAuthDetails{
			IdentityID: kmsDynamicSecret.Spec.Authentication.KubernetesAuth.IdentityID,
			ServiceAccountRef: v1alpha1.KubernetesServiceAccountRef{
				Namespace: kmsDynamicSecret.Spec.Authentication.KubernetesAuth.ServiceAccountRef.Namespace,
				Name:      kmsDynamicSecret.Spec.Authentication.KubernetesAuth.ServiceAccountRef.Name,
			},
			SecretsScope:                  v1alpha1.MachineIdentityScopeInWorkspace{},
			AutoCreateServiceAccountToken: kmsDynamicSecret.Spec.Authentication.KubernetesAuth.AutoCreateServiceAccountToken,
			ServiceAccountTokenAudiences:  kmsDynamicSecret.Spec.Authentication.KubernetesAuth.ServiceAccountTokenAudiences,
		}
	}

	if kubernetesAuthSpec.IdentityID == "" {
		return AuthenticationDetails{}, ErrAuthNotApplicable
	}

	serviceAccountToken, err := GetServiceAccountToken(
		reconcilerClient,
		kubernetesAuthSpec.ServiceAccountRef.Namespace,
		kubernetesAuthSpec.ServiceAccountRef.Name,
		kubernetesAuthSpec.AutoCreateServiceAccountToken,
		kubernetesAuthSpec.ServiceAccountTokenAudiences,
	)

	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("unable to get service account token [err=%s]", err)
	}

	_, err = kmsClient.Auth().KubernetesRawServiceAccountTokenLogin(kubernetesAuthSpec.IdentityID, serviceAccountToken)
	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("unable to login with Kubernetes native auth [err=%s]", err)
	}

	return AuthenticationDetails{
		AuthStrategy:          AuthStrategy.KUBERNETES_MACHINE_IDENTITY,
		MachineIdentityScope:  kubernetesAuthSpec.SecretsScope,
		IsMachineIdentityAuth: true,
		SecretType:            secretCrd.Type,
	}, nil

}

func HandleAwsIamAuth(ctx context.Context, reconcilerClient client.Client, secretCrd SecretAuthInput, kmsClient kmsSdk.KMSClientInterface) (AuthenticationDetails, error) {
	awsIamAuthSpec := v1alpha1.AWSIamAuthDetails{}

	switch secretCrd.Type {
	case SecretCrd.KMS_SECRET:
		kmsSecret, ok := secretCrd.Secret.(v1alpha1.KMSSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSSecret")
		}

		awsIamAuthSpec = kmsSecret.Spec.Authentication.AwsIamAuth
	case SecretCrd.KMS_PUSH_SECRET:
		kmsPushSecret, ok := secretCrd.Secret.(v1alpha1.KMSPushSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSPushSecret")
		}

		awsIamAuthSpec = v1alpha1.AWSIamAuthDetails{
			IdentityID:   kmsPushSecret.Spec.Authentication.AwsIamAuth.IdentityID,
			SecretsScope: v1alpha1.MachineIdentityScopeInWorkspace{},
		}

	case SecretCrd.KMS_DYNAMIC_SECRET:
		kmsDynamicSecret, ok := secretCrd.Secret.(v1alpha1.KMSDynamicSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSDynamicSecret")
		}

		awsIamAuthSpec = v1alpha1.AWSIamAuthDetails{
			IdentityID:   kmsDynamicSecret.Spec.Authentication.AwsIamAuth.IdentityID,
			SecretsScope: v1alpha1.MachineIdentityScopeInWorkspace{},
		}
	}

	if awsIamAuthSpec.IdentityID == "" {
		return AuthenticationDetails{}, ErrAuthNotApplicable
	}

	_, err := kmsClient.Auth().AwsIamAuthLogin(awsIamAuthSpec.IdentityID)
	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("unable to login with AWS IAM auth [err=%s]", err)
	}

	return AuthenticationDetails{
		AuthStrategy:          AuthStrategy.AWS_IAM_MACHINE_IDENTITY,
		MachineIdentityScope:  awsIamAuthSpec.SecretsScope,
		IsMachineIdentityAuth: true,
		SecretType:            secretCrd.Type,
	}, nil

}

func HandleAzureAuth(ctx context.Context, reconcilerClient client.Client, secretCrd SecretAuthInput, kmsClient kmsSdk.KMSClientInterface) (AuthenticationDetails, error) {
	azureAuthSpec := v1alpha1.AzureAuthDetails{}

	switch secretCrd.Type {
	case SecretCrd.KMS_SECRET:
		kmsSecret, ok := secretCrd.Secret.(v1alpha1.KMSSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSSecret")
		}

		azureAuthSpec = kmsSecret.Spec.Authentication.AzureAuth

	case SecretCrd.KMS_PUSH_SECRET:
		kmsPushSecret, ok := secretCrd.Secret.(v1alpha1.KMSPushSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSPushSecret")
		}

		azureAuthSpec = v1alpha1.AzureAuthDetails{
			IdentityID:   kmsPushSecret.Spec.Authentication.AzureAuth.IdentityID,
			Resource:     kmsPushSecret.Spec.Authentication.AzureAuth.Resource,
			SecretsScope: v1alpha1.MachineIdentityScopeInWorkspace{},
		}

	case SecretCrd.KMS_DYNAMIC_SECRET:
		kmsDynamicSecret, ok := secretCrd.Secret.(v1alpha1.KMSDynamicSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSDynamicSecret")
		}

		azureAuthSpec = v1alpha1.AzureAuthDetails{
			IdentityID:   kmsDynamicSecret.Spec.Authentication.AzureAuth.IdentityID,
			Resource:     kmsDynamicSecret.Spec.Authentication.AzureAuth.Resource,
			SecretsScope: v1alpha1.MachineIdentityScopeInWorkspace{},
		}
	}

	if azureAuthSpec.IdentityID == "" {
		return AuthenticationDetails{}, ErrAuthNotApplicable
	}

	_, err := kmsClient.Auth().AzureAuthLogin(azureAuthSpec.IdentityID, azureAuthSpec.Resource) // If resource is empty(""), it will default to "https://management.azure.com/" in the SDK.
	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("unable to login with Azure auth [err=%s]", err)
	}

	return AuthenticationDetails{
		AuthStrategy:          AuthStrategy.AZURE_MACHINE_IDENTITY,
		MachineIdentityScope:  azureAuthSpec.SecretsScope,
		IsMachineIdentityAuth: true,
		SecretType:            secretCrd.Type,
	}, nil

}

func HandleGcpIdTokenAuth(ctx context.Context, reconcilerClient client.Client, secretCrd SecretAuthInput, kmsClient kmsSdk.KMSClientInterface) (AuthenticationDetails, error) {
	gcpIdTokenSpec := v1alpha1.GCPIdTokenAuthDetails{}

	switch secretCrd.Type {
	case SecretCrd.KMS_SECRET:
		kmsSecret, ok := secretCrd.Secret.(v1alpha1.KMSSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSSecret")
		}

		gcpIdTokenSpec = kmsSecret.Spec.Authentication.GcpIdTokenAuth
	case SecretCrd.KMS_PUSH_SECRET:
		kmsPushSecret, ok := secretCrd.Secret.(v1alpha1.KMSPushSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSPushSecret")
		}

		gcpIdTokenSpec = v1alpha1.GCPIdTokenAuthDetails{
			IdentityID:   kmsPushSecret.Spec.Authentication.GcpIdTokenAuth.IdentityID,
			SecretsScope: v1alpha1.MachineIdentityScopeInWorkspace{},
		}

	case SecretCrd.KMS_DYNAMIC_SECRET:
		kmsDynamicSecret, ok := secretCrd.Secret.(v1alpha1.KMSDynamicSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSDynamicSecret")
		}

		gcpIdTokenSpec = v1alpha1.GCPIdTokenAuthDetails{
			IdentityID:   kmsDynamicSecret.Spec.Authentication.GcpIdTokenAuth.IdentityID,
			SecretsScope: v1alpha1.MachineIdentityScopeInWorkspace{},
		}
	}

	if gcpIdTokenSpec.IdentityID == "" {
		return AuthenticationDetails{}, ErrAuthNotApplicable
	}

	_, err := kmsClient.Auth().GcpIdTokenAuthLogin(gcpIdTokenSpec.IdentityID)
	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("unable to login with GCP Id Token auth [err=%s]", err)
	}

	return AuthenticationDetails{
		AuthStrategy:          AuthStrategy.GCP_ID_TOKEN_MACHINE_IDENTITY,
		MachineIdentityScope:  gcpIdTokenSpec.SecretsScope,
		IsMachineIdentityAuth: true,
		SecretType:            secretCrd.Type,
	}, nil

}

func HandleGcpIamAuth(ctx context.Context, reconcilerClient client.Client, secretCrd SecretAuthInput, kmsClient kmsSdk.KMSClientInterface) (AuthenticationDetails, error) {
	gcpIamSpec := v1alpha1.GcpIamAuthDetails{}

	switch secretCrd.Type {
	case SecretCrd.KMS_SECRET:
		kmsSecret, ok := secretCrd.Secret.(v1alpha1.KMSSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSSecret")
		}

		gcpIamSpec = kmsSecret.Spec.Authentication.GcpIamAuth
	case SecretCrd.KMS_PUSH_SECRET:
		kmsPushSecret, ok := secretCrd.Secret.(v1alpha1.KMSPushSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSPushSecret")
		}

		gcpIamSpec = v1alpha1.GcpIamAuthDetails{
			IdentityID:                kmsPushSecret.Spec.Authentication.GcpIamAuth.IdentityID,
			ServiceAccountKeyFilePath: kmsPushSecret.Spec.Authentication.GcpIamAuth.ServiceAccountKeyFilePath,
			SecretsScope:              v1alpha1.MachineIdentityScopeInWorkspace{},
		}

	case SecretCrd.KMS_DYNAMIC_SECRET:
		kmsDynamicSecret, ok := secretCrd.Secret.(v1alpha1.KMSDynamicSecret)

		if !ok {
			return AuthenticationDetails{}, errors.New("unable to cast secret to KMSDynamicSecret")
		}

		gcpIamSpec = v1alpha1.GcpIamAuthDetails{
			IdentityID:                kmsDynamicSecret.Spec.Authentication.GcpIamAuth.IdentityID,
			ServiceAccountKeyFilePath: kmsDynamicSecret.Spec.Authentication.GcpIamAuth.ServiceAccountKeyFilePath,
			SecretsScope:              v1alpha1.MachineIdentityScopeInWorkspace{},
		}
	}

	if gcpIamSpec.IdentityID == "" && gcpIamSpec.ServiceAccountKeyFilePath == "" {
		return AuthenticationDetails{}, ErrAuthNotApplicable
	}

	_, err := kmsClient.Auth().GcpIamAuthLogin(gcpIamSpec.IdentityID, gcpIamSpec.ServiceAccountKeyFilePath)
	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("unable to login with GCP IAM auth [err=%s]", err)
	}

	return AuthenticationDetails{
		AuthStrategy:          AuthStrategy.GCP_IAM_MACHINE_IDENTITY,
		MachineIdentityScope:  gcpIamSpec.SecretsScope,
		IsMachineIdentityAuth: true,
		SecretType:            secretCrd.Type,
	}, nil
}
