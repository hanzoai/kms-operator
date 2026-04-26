// Package controllers/kmssecret_helper.go: read-side reconciler.
//
// The reconciler:
//
//  1. Loads (or reuses) a kmsapi.Client per CR UID.
//  2. Resolves universalAuth credentials (the only supported strategy) and
//     mints a bearer token via cached login.
//  3. Fetches every key listed in secretsScope.keys via single-secret GETs.
//  4. Empty-fetch fail-closed: refuses to project an empty Secret.
//  5. Applies the templating engine and writes / updates the managed
//     Kubernetes Secret(s) and ConfigMap(s).
//
// Removed (forward break):
//   - service-token / service-account auth (no canonical surface).
//   - kubernetes/AWS IAM/Azure/GCP machine-identity auth (no canonical
//     surface — restore only when kmsd grows the routes).
//   - github.com/luxfi/kms-go SDK dep.
package controllers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	tpl "text/template"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"

	"github.com/hanzoai/kms-operator/api/v1alpha1"
	"github.com/hanzoai/kms-operator/packages/api"
	"github.com/hanzoai/kms-operator/packages/constants"
	"github.com/hanzoai/kms-operator/packages/crypto"
	"github.com/hanzoai/kms-operator/packages/kmsapi"
	"github.com/hanzoai/kms-operator/packages/model"
	"github.com/hanzoai/kms-operator/packages/template"
	"github.com/hanzoai/kms-operator/packages/util"

	corev1 "k8s.io/api/core/v1"
	k8Errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// handleAuthentication resolves the universalAuth credentialsRef on the CR
// and returns a fresh bearer token bound to the configured host.
func (r *KMSSecretReconciler) handleAuthentication(
	ctx context.Context,
	kmsSecret v1alpha1.KMSSecret,
	host string,
	kmsClient *kmsapi.Client,
) (util.AuthenticationDetails, error) {

	authDetails, err := util.HandleUniversalAuth(ctx, r.Client, util.SecretAuthInput{
		Secret: kmsSecret,
		Type:   util.SecretCrd.KMS_SECRET,
	}, host, kmsClient)

	if err == nil {
		return authDetails, nil
	}
	if errors.Is(err, util.ErrAuthNotApplicable) {
		return util.AuthenticationDetails{}, errors.New(
			"no authentication method provided — KMSSecret.spec.authentication.universalAuth.credentialsRef is required",
		)
	}
	return util.AuthenticationDetails{}, err
}

func (r *KMSSecretReconciler) getKMSCaCertificateFromKubeSecret(
	ctx context.Context,
	kmsSecret v1alpha1.KMSSecret,
) (string, error) {
	caCertificateFromKubeSecret, err := util.GetKubeSecretByNamespacedName(ctx, r.Client, types.NamespacedName{
		Namespace: kmsSecret.Spec.TLS.CaRef.SecretNamespace,
		Name:      kmsSecret.Spec.TLS.CaRef.SecretName,
	})

	if k8Errors.IsNotFound(err) {
		return "", fmt.Errorf("kubernetes secret containing custom CA certificate cannot be found. [err=%s]", err)
	}
	if err != nil {
		return "", fmt.Errorf("something went wrong when fetching your CA certificate [err=%s]", err)
	}

	return string(caCertificateFromKubeSecret.Data[kmsSecret.Spec.TLS.CaRef.SecretKey]), nil
}

func convertBinaryToStringMap(binaryMap map[string][]byte) map[string]string {
	stringMap := make(map[string]string, len(binaryMap))
	for k, v := range binaryMap {
		stringMap[k] = string(v)
	}
	return stringMap
}

func (r *KMSSecretReconciler) createKMSManagedKubeResource(
	ctx context.Context,
	logger logr.Logger,
	kmsSecret v1alpha1.KMSSecret,
	managedSecretReferenceInterface interface{},
	secretsFromAPI []model.SingleEnvironmentVariable,
	ETag string,
	resourceType constants.ManagedKubeResourceType,
) error {

	plainProcessedSecrets := make(map[string][]byte)

	var managedTemplateData *v1alpha1.SecretTemplate

	if resourceType == constants.MANAGED_KUBE_RESOURCE_TYPE_SECRET {
		managedTemplateData = managedSecretReferenceInterface.(v1alpha1.ManagedKubeSecretConfig).Template
	} else if resourceType == constants.MANAGED_KUBE_RESOURCE_TYPE_CONFIG_MAP {
		managedTemplateData = managedSecretReferenceInterface.(v1alpha1.ManagedKubeConfigMapConfig).Template
	}

	if managedTemplateData == nil || managedTemplateData.IncludeAllSecrets {
		for _, secret := range secretsFromAPI {
			plainProcessedSecrets[secret.Key] = []byte(secret.Value)
		}
	}

	if managedTemplateData != nil {
		secretKeyValue := make(map[string]model.SecretTemplateOptions)
		for _, secret := range secretsFromAPI {
			secretKeyValue[secret.Key] = model.SecretTemplateOptions{
				Value:      secret.Value,
				SecretPath: secret.SecretPath,
			}
		}

		for templateKey, userTemplate := range managedTemplateData.Data {
			tmpl, err := tpl.New("secret-templates").Funcs(template.GetTemplateFunctions()).Parse(userTemplate)
			if err != nil {
				return fmt.Errorf("unable to compile template: %s [err=%v]", templateKey, err)
			}

			buf := bytes.NewBuffer(nil)
			err = tmpl.Execute(buf, secretKeyValue)
			if err != nil {
				return fmt.Errorf("unable to execute template: %s [err=%v]", templateKey, err)
			}
			plainProcessedSecrets[templateKey] = buf.Bytes()
		}
	}

	labels := map[string]string{}
	for k, v := range kmsSecret.Labels {
		labels[k] = v
	}

	annotations := map[string]string{}
	systemPrefixes := []string{"kubectl.kubernetes.io/", "kubernetes.io/", "k8s.io/", "helm.sh/"}
	for k, v := range kmsSecret.Annotations {
		isSystem := false
		for _, prefix := range systemPrefixes {
			if strings.HasPrefix(k, prefix) {
				isSystem = true
				break
			}
		}
		if !isSystem {
			annotations[k] = v
		}
	}

	if resourceType == constants.MANAGED_KUBE_RESOURCE_TYPE_SECRET {
		managedSecretReference := managedSecretReferenceInterface.(v1alpha1.ManagedKubeSecretConfig)
		annotations[constants.SECRET_VERSION_ANNOTATION] = ETag

		newKubeSecretInstance := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        managedSecretReference.SecretName,
				Namespace:   managedSecretReference.SecretNamespace,
				Annotations: annotations,
				Labels:      labels,
			},
			Type: corev1.SecretType(managedSecretReference.SecretType),
			Data: plainProcessedSecrets,
		}

		if managedSecretReference.CreationPolicy == "Owner" {
			err := ctrl.SetControllerReference(&kmsSecret, newKubeSecretInstance, r.Scheme)
			if err != nil {
				return err
			}
		}

		err := r.Client.Create(ctx, newKubeSecretInstance)
		if err != nil {
			return fmt.Errorf("unable to create the managed Kubernetes secret : %w", err)
		}
		logger.Info(fmt.Sprintf("Successfully created a managed Kubernetes secret with your KMS secrets. Type: %s", managedSecretReference.SecretType))
		return nil
	} else if resourceType == constants.MANAGED_KUBE_RESOURCE_TYPE_CONFIG_MAP {
		managedSecretReference := managedSecretReferenceInterface.(v1alpha1.ManagedKubeConfigMapConfig)

		newKubeConfigMapInstance := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:        managedSecretReference.ConfigMapName,
				Namespace:   managedSecretReference.ConfigMapNamespace,
				Annotations: annotations,
				Labels:      labels,
			},
			Data: convertBinaryToStringMap(plainProcessedSecrets),
		}

		if managedSecretReference.CreationPolicy == "Owner" {
			err := ctrl.SetControllerReference(&kmsSecret, newKubeConfigMapInstance, r.Scheme)
			if err != nil {
				return err
			}
		}

		err := r.Client.Create(ctx, newKubeConfigMapInstance)
		if err != nil {
			return fmt.Errorf("unable to create the managed Kubernetes config map : %w", err)
		}
		logger.Info(fmt.Sprintf("Successfully created a managed Kubernetes config map with your KMS secrets. Type: %s", managedSecretReference.ConfigMapName))
		return nil
	}
	return fmt.Errorf("invalid resource type")
}

func (r *KMSSecretReconciler) updateKMSManagedKubeSecret(
	ctx context.Context,
	logger logr.Logger,
	managedSecretReference v1alpha1.ManagedKubeSecretConfig,
	managedKubeSecret corev1.Secret,
	secretsFromAPI []model.SingleEnvironmentVariable,
	ETag string,
) error {
	managedTemplateData := managedSecretReference.Template

	plainProcessedSecrets := make(map[string][]byte)
	if managedTemplateData == nil || managedTemplateData.IncludeAllSecrets {
		for _, secret := range secretsFromAPI {
			plainProcessedSecrets[secret.Key] = []byte(secret.Value)
		}
	}

	if managedTemplateData != nil {
		secretKeyValue := make(map[string]model.SecretTemplateOptions)
		for _, secret := range secretsFromAPI {
			secretKeyValue[secret.Key] = model.SecretTemplateOptions{
				Value:      secret.Value,
				SecretPath: secret.SecretPath,
			}
		}

		for templateKey, userTemplate := range managedTemplateData.Data {
			tmpl, err := tpl.New("secret-templates").Funcs(template.GetTemplateFunctions()).Parse(userTemplate)
			if err != nil {
				return fmt.Errorf("unable to compile template: %s [err=%v]", templateKey, err)
			}

			buf := bytes.NewBuffer(nil)
			err = tmpl.Execute(buf, secretKeyValue)
			if err != nil {
				return fmt.Errorf("unable to execute template: %s [err=%v]", templateKey, err)
			}
			plainProcessedSecrets[templateKey] = buf.Bytes()
		}
	}

	if managedKubeSecret.ObjectMeta.Annotations == nil {
		managedKubeSecret.ObjectMeta.Annotations = make(map[string]string)
	}

	managedKubeSecret.Data = plainProcessedSecrets
	managedKubeSecret.ObjectMeta.Annotations[constants.SECRET_VERSION_ANNOTATION] = ETag

	err := r.Client.Update(ctx, &managedKubeSecret)
	if err != nil {
		return fmt.Errorf("unable to update Kubernetes secret because [%w]", err)
	}

	logger.Info("successfully updated managed Kubernetes secret")
	return nil
}

func (r *KMSSecretReconciler) updateKMSManagedConfigMap(
	ctx context.Context,
	logger logr.Logger,
	managedConfigMapReference v1alpha1.ManagedKubeConfigMapConfig,
	managedConfigMap corev1.ConfigMap,
	secretsFromAPI []model.SingleEnvironmentVariable,
	ETag string,
) error {
	managedTemplateData := managedConfigMapReference.Template

	plainProcessedSecrets := make(map[string][]byte)
	if managedTemplateData == nil || managedTemplateData.IncludeAllSecrets {
		for _, secret := range secretsFromAPI {
			plainProcessedSecrets[secret.Key] = []byte(secret.Value)
		}
	}

	if managedTemplateData != nil {
		secretKeyValue := make(map[string]model.SecretTemplateOptions)
		for _, secret := range secretsFromAPI {
			secretKeyValue[secret.Key] = model.SecretTemplateOptions{
				Value:      secret.Value,
				SecretPath: secret.SecretPath,
			}
		}

		for templateKey, userTemplate := range managedTemplateData.Data {
			tmpl, err := tpl.New("secret-templates").Funcs(template.GetTemplateFunctions()).Parse(userTemplate)
			if err != nil {
				return fmt.Errorf("unable to compile template: %s [err=%v]", templateKey, err)
			}

			buf := bytes.NewBuffer(nil)
			err = tmpl.Execute(buf, secretKeyValue)
			if err != nil {
				return fmt.Errorf("unable to execute template: %s [err=%v]", templateKey, err)
			}
			plainProcessedSecrets[templateKey] = buf.Bytes()
		}
	}

	if managedConfigMap.ObjectMeta.Annotations == nil {
		managedConfigMap.ObjectMeta.Annotations = make(map[string]string)
	}

	managedConfigMap.Data = convertBinaryToStringMap(plainProcessedSecrets)
	managedConfigMap.ObjectMeta.Annotations[constants.SECRET_VERSION_ANNOTATION] = ETag

	err := r.Client.Update(ctx, &managedConfigMap)
	if err != nil {
		return fmt.Errorf("unable to update Kubernetes config map because [%w]", err)
	}

	logger.Info("successfully updated managed Kubernetes config map")
	return nil
}

func (r *KMSSecretReconciler) fetchSecretsFromAPI(
	ctx context.Context,
	logger logr.Logger,
	authDetails util.AuthenticationDetails,
	kmsClient *kmsapi.Client,
) ([]model.SingleEnvironmentVariable, error) {

	if authDetails.AuthStrategy != util.AuthStrategy.UNIVERSAL_MACHINE_IDENTITY {
		return nil, fmt.Errorf("unsupported authentication strategy %q — only UNIVERSAL_MACHINE_IDENTITY is supported on the canonical luxfi/kms surface", authDetails.AuthStrategy)
	}
	plainText, err := util.GetPlainTextSecretsViaMachineIdentity(
		ctx, kmsClient, authDetails.Host, authDetails.BearerToken, authDetails.MachineIdentityScope,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}
	logger.Info(fmt.Sprintf("ReconcileKMSSecret: fetched %d secret(s) via universalAuth", len(plainText)))
	return plainText, nil
}

func (r *KMSSecretReconciler) getResourceVariables(kmsSecret v1alpha1.KMSSecret) util.ResourceVariables {
	if rv, ok := kmsSecretResourceVariablesMap[string(kmsSecret.UID)]; ok {
		return rv
	}

	_, cancel := context.WithCancel(context.Background())
	cli, err := kmsapi.New(kmsapi.Config{
		CACertPEM: api.API_CA_CERTIFICATE,
		UserAgent: api.USER_AGENT_NAME,
	})
	if err != nil {
		// Fall back to a default-config client; the only failure mode of
		// kmsapi.New is an unparseable CA bundle, which is tracked
		// separately on the next reconcile.
		cli, _ = kmsapi.New(kmsapi.Config{UserAgent: api.USER_AGENT_NAME})
	}

	rv := util.ResourceVariables{
		KMSClient:   cli,
		CancelCtx:   cancel,
		AuthDetails: util.AuthenticationDetails{},
	}
	kmsSecretResourceVariablesMap[string(kmsSecret.UID)] = rv
	return rv
}

func (r *KMSSecretReconciler) updateResourceVariables(kmsSecret v1alpha1.KMSSecret, resourceVariables util.ResourceVariables) {
	kmsSecretResourceVariablesMap[string(kmsSecret.UID)] = resourceVariables
}

// ReconcileKMSSecret runs the full read+project pipeline for a single
// KMSSecret CR.
func (r *KMSSecretReconciler) ReconcileKMSSecret(
	ctx context.Context,
	logger logr.Logger,
	kmsSecret *v1alpha1.KMSSecret,
	managedKubeSecretReferences []v1alpha1.ManagedKubeSecretConfig,
	managedKubeConfigMapReferences []v1alpha1.ManagedKubeConfigMapConfig,
) (int, error) {

	if kmsSecret == nil {
		return 0, fmt.Errorf("kmsSecret is nil")
	}

	resourceVariables := r.getResourceVariables(*kmsSecret)
	kmsClient := resourceVariables.KMSClient
	cancelCtx := resourceVariables.CancelCtx
	authDetails := resourceVariables.AuthDetails
	host := api.API_HOST_URL
	if h := strings.TrimSpace(kmsSecret.Spec.HostAPI); h != "" {
		host = h
	}

	if authDetails.AuthStrategy == "" {
		logger.Info("No authentication strategy found. Attempting to authenticate")
		var err error
		authDetails, err = r.handleAuthentication(ctx, *kmsSecret, host, kmsClient)
		r.SetKMSTokenLoadCondition(ctx, logger, kmsSecret, authDetails.AuthStrategy, err)
		if err != nil {
			return 0, fmt.Errorf("unable to authenticate [err=%s]", err)
		}
		r.updateResourceVariables(*kmsSecret, util.ResourceVariables{
			KMSClient:   kmsClient,
			CancelCtx:   cancelCtx,
			AuthDetails: authDetails,
		})
	}

	plainTextSecretsFromApi, err := r.fetchSecretsFromAPI(ctx, logger, authDetails, kmsClient)
	if err != nil {
		// On any auth-shaped failure, drop the cached token so the next
		// reconcile re-issues login.
		kmsClient.InvalidateToken(authDetails.Host, "", "")
		return 0, fmt.Errorf("failed to fetch secrets from API for managed secrets [err=%s]", err)
	}
	if len(plainTextSecretsFromApi) == 0 {
		return 0, errors.New("empty fetch — refusing to project an empty Secret")
	}
	secretsCount := len(plainTextSecretsFromApi)

	if len(managedKubeSecretReferences) > 0 {
		for _, managedSecretReference := range managedKubeSecretReferences {
			managedKubeSecret, err := util.GetKubeSecretByNamespacedName(ctx, r.Client, types.NamespacedName{
				Name:      managedSecretReference.SecretName,
				Namespace: managedSecretReference.SecretNamespace,
			})
			if err != nil && !k8Errors.IsNotFound(err) {
				return 0, fmt.Errorf("something went wrong when fetching the managed Kubernetes secret [%w]", err)
			}

			newEtag := crypto.ComputeEtag([]byte(fmt.Sprintf("%v", plainTextSecretsFromApi)))
			if managedKubeSecret == nil {
				if err := r.createKMSManagedKubeResource(ctx, logger, *kmsSecret, managedSecretReference, plainTextSecretsFromApi, newEtag, constants.MANAGED_KUBE_RESOURCE_TYPE_SECRET); err != nil {
					return 0, fmt.Errorf("failed to create managed secret [err=%s]", err)
				}
			} else {
				if err := r.updateKMSManagedKubeSecret(ctx, logger, managedSecretReference, *managedKubeSecret, plainTextSecretsFromApi, newEtag); err != nil {
					return 0, fmt.Errorf("failed to update managed secret [err=%s]", err)
				}
			}
		}
	}

	if len(managedKubeConfigMapReferences) > 0 {
		for _, managedConfigMapReference := range managedKubeConfigMapReferences {
			managedKubeConfigMap, err := util.GetKubeConfigMapByNamespacedName(ctx, r.Client, types.NamespacedName{
				Name:      managedConfigMapReference.ConfigMapName,
				Namespace: managedConfigMapReference.ConfigMapNamespace,
			})
			if err != nil && !k8Errors.IsNotFound(err) {
				return 0, fmt.Errorf("something went wrong when fetching the managed Kubernetes config map [%w]", err)
			}

			newEtag := crypto.ComputeEtag([]byte(fmt.Sprintf("%v", plainTextSecretsFromApi)))
			if managedKubeConfigMap == nil {
				if err := r.createKMSManagedKubeResource(ctx, logger, *kmsSecret, managedConfigMapReference, plainTextSecretsFromApi, newEtag, constants.MANAGED_KUBE_RESOURCE_TYPE_CONFIG_MAP); err != nil {
					return 0, fmt.Errorf("failed to create managed config map [err=%s]", err)
				}
			} else {
				if err := r.updateKMSManagedConfigMap(ctx, logger, managedConfigMapReference, *managedKubeConfigMap, plainTextSecretsFromApi, newEtag); err != nil {
					return 0, fmt.Errorf("failed to update managed config map [err=%s]", err)
				}
			}
		}
	}

	return secretsCount, nil
}
