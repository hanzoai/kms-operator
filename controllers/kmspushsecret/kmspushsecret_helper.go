// Package controllers/kmspushsecret_helper.go: write-side reconciler.
//
// Pushes a Kubernetes Secret + (optional) generator output to the
// canonical luxfi/kms surface as one secret per key. The canonical
// surface has no list/discovery endpoint and no opaque secret ID —
// every value is addressed by exact (org, env, path, name).
//
// Reconciler model:
//
//   - status.ManagedSecrets[name] = name (the names this CR has
//     pushed; values are the same — the field is a Set).
//   - For each desired key: GET. On 404, POST (create). On 200, PATCH
//     with If-Match version CAS only if the new value differs.
//   - Drift: any name in status.ManagedSecrets that is no longer in
//     the desired set is DELETEd from KMS, and dropped from the map.
//
// All input/output passes the kmsapi control-byte filter; oversize
// scopes (org/env/path/name) are rejected before any URL is built.
package controllers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	tpl "text/template"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8Errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	"github.com/hanzoai/kms-operator/api/v1alpha1"
	"github.com/hanzoai/kms-operator/packages/api"
	"github.com/hanzoai/kms-operator/packages/constants"
	generatorUtil "github.com/hanzoai/kms-operator/packages/generator"
	"github.com/hanzoai/kms-operator/packages/kmsapi"
	"github.com/hanzoai/kms-operator/packages/model"
	"github.com/hanzoai/kms-operator/packages/template"
	"github.com/hanzoai/kms-operator/packages/util"
)

func (r *KMSPushSecretReconciler) handleAuthentication(
	ctx context.Context,
	kmsSecret v1alpha1.KMSPushSecret,
	host string,
	kmsClient *kmsapi.Client,
) (util.AuthenticationDetails, error) {

	authDetails, err := util.HandleUniversalAuth(ctx, r.Client, util.SecretAuthInput{
		Secret: kmsSecret,
		Type:   util.SecretCrd.KMS_PUSH_SECRET,
	}, host, kmsClient)

	if err == nil {
		return authDetails, nil
	}
	if errors.Is(err, util.ErrAuthNotApplicable) {
		return util.AuthenticationDetails{}, errors.New(
			"no authentication method provided — KMSPushSecret.spec.authentication.universalAuth.credentialsRef is required",
		)
	}
	return util.AuthenticationDetails{}, err
}

func (r *KMSPushSecretReconciler) getKMSCaCertificateFromKubeSecret(
	ctx context.Context,
	kmsSecret v1alpha1.KMSPushSecret,
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

func (r *KMSPushSecretReconciler) getResourceVariables(kmsPushSecret v1alpha1.KMSPushSecret) util.ResourceVariables {
	if rv, ok := kmsPushSecretResourceVariablesMap[string(kmsPushSecret.UID)]; ok {
		return rv
	}

	_, cancel := context.WithCancel(context.Background())
	cli, err := kmsapi.New(kmsapi.Config{
		CACertPEM: api.API_CA_CERTIFICATE,
		UserAgent: api.USER_AGENT_NAME,
	})
	if err != nil {
		cli, _ = kmsapi.New(kmsapi.Config{UserAgent: api.USER_AGENT_NAME})
	}

	rv := util.ResourceVariables{
		KMSClient:   cli,
		CancelCtx:   cancel,
		AuthDetails: util.AuthenticationDetails{},
	}
	kmsPushSecretResourceVariablesMap[string(kmsPushSecret.UID)] = rv
	return rv
}

func (r *KMSPushSecretReconciler) updateResourceVariables(kmsPushSecret v1alpha1.KMSPushSecret, resourceVariables util.ResourceVariables) {
	kmsPushSecretResourceVariablesMap[string(kmsPushSecret.UID)] = resourceVariables
}

func (r *KMSPushSecretReconciler) processGenerators(ctx context.Context, kmsPushSecret v1alpha1.KMSPushSecret) (map[string]string, error) {

	processedSecrets := make(map[string]string)

	if len(kmsPushSecret.Spec.Push.Generators) == 0 {
		return processedSecrets, nil
	}

	for _, generator := range kmsPushSecret.Spec.Push.Generators {
		generatorRef := generator.GeneratorRef

		clusterGenerator := &v1alpha1.ClusterGenerator{}
		err := r.Client.Get(ctx, types.NamespacedName{Name: generatorRef.Name}, clusterGenerator)
		if err != nil {
			return nil, fmt.Errorf("unable to get ClusterGenerator resource [err=%s]", err)
		}
		if generatorRef.Kind == v1alpha1.GeneratorKindPassword {
			if clusterGenerator.Spec.Generator.PasswordSpec == nil {
				return nil, fmt.Errorf("password spec is not defined in the ClusterGenerator resource")
			}
			password, err := generatorUtil.GeneratorPassword(*clusterGenerator.Spec.Generator.PasswordSpec)
			if err != nil {
				return nil, fmt.Errorf("unable to generate password [err=%s]", err)
			}
			processedSecrets[generator.DestinationSecretName] = password
		}

		if generatorRef.Kind == v1alpha1.GeneratorKindUUID {
			uuid, err := generatorUtil.GeneratorUUID()
			if err != nil {
				return nil, fmt.Errorf("unable to generate UUID [err=%s]", err)
			}
			processedSecrets[generator.DestinationSecretName] = uuid
		}
	}

	return processedSecrets, nil
}

func (r *KMSPushSecretReconciler) processTemplatedSecrets(
	kmsPushSecret v1alpha1.KMSPushSecret,
	kubePushSecret *corev1.Secret,
	destination v1alpha1.KMSPushSecretDestination,
) (map[string]string, error) {

	processedSecrets := make(map[string]string)

	sourceSecrets := make(map[string]model.SecretTemplateOptions)
	for key, value := range kubePushSecret.Data {
		sourceSecrets[key] = model.SecretTemplateOptions{
			Value:      string(value),
			SecretPath: destination.SecretsPath,
		}
	}

	if kmsPushSecret.Spec.Push.Secret.Template == nil ||
		(kmsPushSecret.Spec.Push.Secret.Template != nil && kmsPushSecret.Spec.Push.Secret.Template.IncludeAllSecrets) {
		for key, value := range kubePushSecret.Data {
			processedSecrets[key] = string(value)
		}
	}

	if kmsPushSecret.Spec.Push.Secret.Template != nil &&
		len(kmsPushSecret.Spec.Push.Secret.Template.Data) > 0 {

		for templateKey, userTemplate := range kmsPushSecret.Spec.Push.Secret.Template.Data {
			tmpl, err := tpl.New("push-secret-templates").Funcs(template.GetTemplateFunctions()).Parse(userTemplate)
			if err != nil {
				return nil, fmt.Errorf("unable to compile template: %s [err=%v]", templateKey, err)
			}

			buf := bytes.NewBuffer(nil)
			err = tmpl.Execute(buf, sourceSecrets)
			if err != nil {
				return nil, fmt.Errorf("unable to execute template: %s [err=%v]", templateKey, err)
			}

			processedSecrets[templateKey] = buf.String()
		}
	}

	return processedSecrets, nil
}

// ReconcileKMSPushSecret converges the KMS state with the desired set
// of secrets derived from spec.push.secret + spec.push.generators.
//
// Drift handling: any name in status.ManagedSecrets that is not in the
// fresh desired set is DELETEd from KMS so the stale value cannot be
// re-fetched by a downstream consumer. New keys are POSTed; existing
// keys are PATCHed only if the value changed (read-modify-write).
func (r *KMSPushSecretReconciler) ReconcileKMSPushSecret(
	ctx context.Context,
	logger logr.Logger,
	kmsPushSecret v1alpha1.KMSPushSecret,
) error {

	resourceVariables := r.getResourceVariables(kmsPushSecret)
	kmsClient := resourceVariables.KMSClient
	cancelCtx := resourceVariables.CancelCtx
	authDetails := resourceVariables.AuthDetails
	host := api.API_HOST_URL
	if h := strings.TrimSpace(kmsPushSecret.Spec.HostAPI); h != "" {
		host = h
	}

	if authDetails.AuthStrategy == "" {
		var err error
		logger.Info("No authentication strategy found. Attempting to authenticate")
		authDetails, err = r.handleAuthentication(ctx, kmsPushSecret, host, kmsClient)
		r.SetAuthenticatedStatusCondition(ctx, &kmsPushSecret, err)
		if err != nil {
			return fmt.Errorf("unable to authenticate [err=%s]", err)
		}
		r.updateResourceVariables(kmsPushSecret, util.ResourceVariables{
			KMSClient:   kmsClient,
			CancelCtx:   cancelCtx,
			AuthDetails: authDetails,
		})
	}

	processedSecrets := make(map[string]string)
	if kmsPushSecret.Spec.Push.Secret != nil {
		kubePushSecret, err := util.GetKubeSecretByNamespacedName(ctx, r.Client, types.NamespacedName{
			Namespace: kmsPushSecret.Spec.Push.Secret.SecretNamespace,
			Name:      kmsPushSecret.Spec.Push.Secret.SecretName,
		})
		if err != nil {
			return fmt.Errorf("unable to fetch kube secret [err=%s]", err)
		}

		processedSecrets, err = r.processTemplatedSecrets(kmsPushSecret, kubePushSecret, kmsPushSecret.Spec.Destination)
		if err != nil {
			return fmt.Errorf("unable to process templated secrets [err=%s]", err)
		}
	}

	generatorSecrets, err := r.processGenerators(ctx, kmsPushSecret)
	if err != nil {
		return fmt.Errorf("unable to process generators [err=%s]", err)
	}
	for key, value := range generatorSecrets {
		processedSecrets[key] = value
	}

	destination := kmsPushSecret.Spec.Destination
	updatePolicy := kmsPushSecret.Spec.UpdatePolicy
	canReplace := updatePolicy == string(constants.PUSH_SECRET_REPLACE_POLICY_ENABLED)

	var (
		secretsFailedToCreate []string
		secretsFailedToUpdate []string
		secretsFailedToDelete []string
	)

	if kmsPushSecret.Status.ManagedSecrets == nil {
		kmsPushSecret.Status.ManagedSecrets = make(map[string]string)
	}

	// 1. Create / update every desired key.
	for key, value := range processedSecrets {
		// Read the current value first so we know whether to POST or PATCH.
		current, getErr := kmsClient.GetSecret(ctx, host, authDetails.BearerToken, destination.ProjectID, destination.EnvironmentSlug, destination.SecretsPath, key)
		switch {
		case errors.Is(getErr, kmsapi.ErrNotFound):
			// Create.
			if _, err := kmsClient.CreateSecret(ctx, host, authDetails.BearerToken, destination.ProjectID, destination.EnvironmentSlug, destination.SecretsPath, key, value); err != nil {
				secretsFailedToCreate = append(secretsFailedToCreate, key)
				logger.Info(fmt.Sprintf("unable to create secret [key=%s] [err=%s]", key, err))
				continue
			}
			kmsPushSecret.Status.ManagedSecrets[key] = key

		case getErr != nil:
			secretsFailedToUpdate = append(secretsFailedToUpdate, key)
			logger.Info(fmt.Sprintf("unable to read existing secret [key=%s] [err=%s]", key, getErr))
			continue

		default:
			// Found. Update only if (a) we manage it, OR (b) replace
			// policy is enabled. Skip silently otherwise — same
			// semantics as the legacy reconciler.
			_, weManageIt := kmsPushSecret.Status.ManagedSecrets[key]
			mayUpdate := weManageIt || canReplace
			if !mayUpdate {
				continue
			}
			if current.Value == value {
				// No-op write would still bump version unnecessarily.
				kmsPushSecret.Status.ManagedSecrets[key] = key
				continue
			}
			if _, err := kmsClient.UpdateSecret(ctx, host, authDetails.BearerToken, destination.ProjectID, destination.EnvironmentSlug, destination.SecretsPath, key, value, current.Version); err != nil {
				secretsFailedToUpdate = append(secretsFailedToUpdate, key)
				logger.Info(fmt.Sprintf("unable to update secret [key=%s] [err=%s]", key, err))
				continue
			}
			kmsPushSecret.Status.ManagedSecrets[key] = key
		}
	}

	// 2. Drift: drop any managed key that is no longer in the desired
	// set. The canonical server returns 404 if it was already gone;
	// treat that as success and prune the local roster.
	for managedKey := range kmsPushSecret.Status.ManagedSecrets {
		if _, stillDesired := processedSecrets[managedKey]; stillDesired {
			continue
		}
		err := kmsClient.DeleteSecret(ctx, host, authDetails.BearerToken, destination.ProjectID, destination.EnvironmentSlug, destination.SecretsPath, managedKey)
		if err != nil && !errors.Is(err, kmsapi.ErrNotFound) {
			secretsFailedToDelete = append(secretsFailedToDelete, managedKey)
			logger.Info(fmt.Sprintf("unable to delete secret [key=%s] [err=%s]", managedKey, err))
			continue
		}
		delete(kmsPushSecret.Status.ManagedSecrets, managedKey)
	}

	r.SetFailedToCreateSecretsStatusCondition(ctx, &kmsPushSecret, joinIfAny("Failed to create secrets: ", secretsFailedToCreate))
	r.SetFailedToUpdateSecretsStatusCondition(ctx, &kmsPushSecret, joinIfAny("Failed to update secrets: ", secretsFailedToUpdate))
	r.SetFailedToDeleteSecretsStatusCondition(ctx, &kmsPushSecret, joinIfAny("Failed to delete secrets: ", secretsFailedToDelete))
	// SetFailedToReplaceSecretsStatusCondition is retained for status-API
	// compatibility but is no longer reachable on the canonical surface
	// (no rename-by-id semantics exist).
	r.SetFailedToReplaceSecretsStatusCondition(ctx, &kmsPushSecret, "")

	if err := r.Client.Status().Update(ctx, &kmsPushSecret); err != nil {
		return fmt.Errorf("unable to update status of KMSPushSecret [err=%s]", err)
	}
	return nil
}

func (r *KMSPushSecretReconciler) DeleteManagedSecrets(
	ctx context.Context,
	logger logr.Logger,
	kmsPushSecret v1alpha1.KMSPushSecret,
) error {
	if kmsPushSecret.Spec.DeletionPolicy != string(constants.PUSH_SECRET_DELETE_POLICY_ENABLED) {
		return nil
	}

	resourceVariables := r.getResourceVariables(kmsPushSecret)
	kmsClient := resourceVariables.KMSClient
	cancelCtx := resourceVariables.CancelCtx
	authDetails := resourceVariables.AuthDetails
	host := api.API_HOST_URL
	if h := strings.TrimSpace(kmsPushSecret.Spec.HostAPI); h != "" {
		host = h
	}

	if authDetails.AuthStrategy == "" {
		logger.Info("No authentication strategy found. Attempting to authenticate")
		var err error
		authDetails, err = r.handleAuthentication(ctx, kmsPushSecret, host, kmsClient)
		r.SetAuthenticatedStatusCondition(ctx, &kmsPushSecret, err)
		if err != nil {
			return fmt.Errorf("unable to authenticate [err=%s]", err)
		}
		r.updateResourceVariables(kmsPushSecret, util.ResourceVariables{
			KMSClient:   kmsClient,
			CancelCtx:   cancelCtx,
			AuthDetails: authDetails,
		})
	}

	destination := kmsPushSecret.Spec.Destination
	for managedKey := range kmsPushSecret.Status.ManagedSecrets {
		err := kmsClient.DeleteSecret(ctx, host, authDetails.BearerToken, destination.ProjectID, destination.EnvironmentSlug, destination.SecretsPath, managedKey)
		if err != nil && !errors.Is(err, kmsapi.ErrNotFound) {
			logger.Info(fmt.Sprintf("unable to delete secret [key=%s] [err=%s]", managedKey, err))
			continue
		}
	}
	return nil
}

func joinIfAny(prefix string, items []string) string {
	if len(items) == 0 {
		return ""
	}
	return prefix + "[" + strings.Join(items, ", ") + "]"
}
