package controllers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	tpl "text/template"

	"github.com/luxfi/kms/k8-operator/api/v1alpha1"
	"github.com/luxfi/kms/k8-operator/packages/api"
	"github.com/luxfi/kms/k8-operator/packages/constants"
	"github.com/luxfi/kms/k8-operator/packages/model"
	"github.com/luxfi/kms/k8-operator/packages/template"
	"github.com/luxfi/kms/k8-operator/packages/util"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	generatorUtil "github.com/luxfi/kms/k8-operator/packages/generator"
	kmsSdk "github.com/luxfi/kms-go"
	k8Errors "k8s.io/apimachinery/pkg/api/errors"
)

func (r *KMSPushSecretReconciler) handleAuthentication(ctx context.Context, kmsSecret v1alpha1.KMSPushSecret, kmsClient kmsSdk.KMSClientInterface) (util.AuthenticationDetails, error) {
	authStrategies := map[util.AuthStrategyType]func(ctx context.Context, reconcilerClient client.Client, secretCrd util.SecretAuthInput, kmsClient kmsSdk.KMSClientInterface) (util.AuthenticationDetails, error){
		util.AuthStrategy.UNIVERSAL_MACHINE_IDENTITY:    util.HandleUniversalAuth,
		util.AuthStrategy.KUBERNETES_MACHINE_IDENTITY:   util.HandleKubernetesAuth,
		util.AuthStrategy.AWS_IAM_MACHINE_IDENTITY:      util.HandleAwsIamAuth,
		util.AuthStrategy.AZURE_MACHINE_IDENTITY:        util.HandleAzureAuth,
		util.AuthStrategy.GCP_ID_TOKEN_MACHINE_IDENTITY: util.HandleGcpIdTokenAuth,
		util.AuthStrategy.GCP_IAM_MACHINE_IDENTITY:      util.HandleGcpIamAuth,
	}

	for authStrategy, authHandler := range authStrategies {
		authDetails, err := authHandler(ctx, r.Client, util.SecretAuthInput{
			Secret: kmsSecret,
			Type:   util.SecretCrd.KMS_PUSH_SECRET,
		}, kmsClient)

		if err == nil {
			return authDetails, nil
		}

		if !errors.Is(err, util.ErrAuthNotApplicable) {
			return util.AuthenticationDetails{}, fmt.Errorf("authentication failed for strategy [%s] [err=%w]", authStrategy, err)
		}
	}

	return util.AuthenticationDetails{}, fmt.Errorf("no authentication method provided")

}

func (r *KMSPushSecretReconciler) getKMSCaCertificateFromKubeSecret(ctx context.Context, kmsSecret v1alpha1.KMSPushSecret) (caCertificate string, err error) {

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

	caCertificateFromSecret := string(caCertificateFromKubeSecret.Data[kmsSecret.Spec.TLS.CaRef.SecretKey])

	return caCertificateFromSecret, nil
}

func (r *KMSPushSecretReconciler) getResourceVariables(kmsPushSecret v1alpha1.KMSPushSecret) util.ResourceVariables {

	var resourceVariables util.ResourceVariables

	if _, ok := kmsPushSecretResourceVariablesMap[string(kmsPushSecret.UID)]; !ok {

		ctx, cancel := context.WithCancel(context.Background())

		client := kmsSdk.NewKMSClient(ctx, kmsSdk.Config{
			SiteUrl:       api.API_HOST_URL,
			CaCertificate: api.API_CA_CERTIFICATE,
			UserAgent:     api.USER_AGENT_NAME,
		})

		kmsPushSecretResourceVariablesMap[string(kmsPushSecret.UID)] = util.ResourceVariables{
			KMSClient: client,
			CancelCtx:       cancel,
			AuthDetails:     util.AuthenticationDetails{},
		}

		resourceVariables = kmsPushSecretResourceVariablesMap[string(kmsPushSecret.UID)]

	} else {
		resourceVariables = kmsPushSecretResourceVariablesMap[string(kmsPushSecret.UID)]
	}

	return resourceVariables

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
			// get the custom ClusterGenerator resource from the cluster

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

func (r *KMSPushSecretReconciler) processTemplatedSecrets(kmsPushSecret v1alpha1.KMSPushSecret, kubePushSecret *corev1.Secret, destination v1alpha1.KMSPushSecretDestination) (map[string]string, error) {

	processedSecrets := make(map[string]string)

	sourceSecrets := make(map[string]model.SecretTemplateOptions)
	for key, value := range kubePushSecret.Data {

		sourceSecrets[key] = model.SecretTemplateOptions{
			Value:      string(value),
			SecretPath: destination.SecretsPath,
		}
	}

	if kmsPushSecret.Spec.Push.Secret.Template == nil || (kmsPushSecret.Spec.Push.Secret.Template != nil && kmsPushSecret.Spec.Push.Secret.Template.IncludeAllSecrets) {
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

func (r *KMSPushSecretReconciler) ReconcileKMSPushSecret(ctx context.Context, logger logr.Logger, kmsPushSecret v1alpha1.KMSPushSecret) error {

	resourceVariables := r.getResourceVariables(kmsPushSecret)
	kmsClient := resourceVariables.KMSClient
	cancelCtx := resourceVariables.CancelCtx
	authDetails := resourceVariables.AuthDetails
	var err error

	if authDetails.AuthStrategy == "" {
		logger.Info("No authentication strategy found. Attempting to authenticate")
		authDetails, err = r.handleAuthentication(ctx, kmsPushSecret, kmsClient)
		r.SetAuthenticatedStatusCondition(ctx, &kmsPushSecret, err)

		if err != nil {
			return fmt.Errorf("unable to authenticate [err=%s]", err)
		}

		r.updateResourceVariables(kmsPushSecret, util.ResourceVariables{
			KMSClient: kmsClient,
			CancelCtx:       cancelCtx,
			AuthDetails:     authDetails,
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
	existingSecrets, err := kmsClient.Secrets().List(kmsSdk.ListSecretsOptions{
		ProjectID:      destination.ProjectID,
		Environment:    destination.EnvironmentSlug,
		SecretPath:     destination.SecretsPath,
		IncludeImports: false,
	})

	getExistingSecretByKey := func(key string) *kmsSdk.Secret {
		for _, secret := range existingSecrets {
			if secret.SecretKey == key {
				return &secret
			}
		}
		return nil
	}

	getExistingSecretById := func(id string) *kmsSdk.Secret {
		for _, secret := range existingSecrets {
			if secret.ID == id {
				return &secret
			}
		}
		return nil
	}

	updateExistingSecretByKey := func(key string, newSecretValue string) {
		for i := range existingSecrets {
			if existingSecrets[i].SecretKey == key {
				existingSecrets[i].SecretValue = newSecretValue
				break
			}
		}
	}

	if err != nil {
		return fmt.Errorf("unable to list secrets [err=%s]", err)
	}

	updatePolicy := kmsPushSecret.Spec.UpdatePolicy

	var secretsFailedToCreate []string
	var secretsFailedToUpdate []string
	var secretsFailedToDelete []string
	var secretsFailedToReplaceById []string

	// If the ManagedSecrets are nil, we know this is the first time the KMSPushSecret is being reconciled.
	if kmsPushSecret.Status.ManagedSecrets == nil {

		kmsPushSecret.Status.ManagedSecrets = make(map[string]string) // (string[id], string[key] )

		for secretKey, secretValue := range processedSecrets {
			if exists := getExistingSecretByKey(secretKey); exists != nil {

				if updatePolicy == string(constants.PUSH_SECRET_REPLACE_POLICY_ENABLED) {
					updatedSecret, err := kmsClient.Secrets().Update(kmsSdk.UpdateSecretOptions{
						SecretKey:      secretKey,
						ProjectID:      destination.ProjectID,
						Environment:    destination.EnvironmentSlug,
						SecretPath:     destination.SecretsPath,
						NewSecretValue: secretValue,
					})

					if err != nil {
						secretsFailedToUpdate = append(secretsFailedToUpdate, secretKey)
						logger.Info(fmt.Sprintf("unable to update secret [key=%s] [err=%s]", secretKey, err))
						continue
					}

					kmsPushSecret.Status.ManagedSecrets[updatedSecret.ID] = secretKey
				}
			} else {
				createdSecret, err := kmsClient.Secrets().Create(kmsSdk.CreateSecretOptions{
					SecretKey:   secretKey,
					SecretValue: secretValue,
					ProjectID:   destination.ProjectID,
					Environment: destination.EnvironmentSlug,
					SecretPath:  destination.SecretsPath,
				})

				if err != nil {
					secretsFailedToCreate = append(secretsFailedToCreate, secretKey)
					logger.Info(fmt.Sprintf("unable to create secret [key=%s] [err=%s]", secretKey, err))
					continue
				}

				kmsPushSecret.Status.ManagedSecrets[createdSecret.ID] = secretKey
			}
		}
	} else {

		// Loop over all the managed secrets, and find the corresponding existingSecret that has the same ID. If the key doesn't match, delete the secret, and re-create it with the correct key/value
		for managedSecretId, managedSecretKey := range kmsPushSecret.Status.ManagedSecrets {

			existingSecret := getExistingSecretById(managedSecretId)

			if existingSecret != nil {

				if existingSecret.SecretKey != managedSecretKey {
					// Secret key has changed, lets delete the secret and re-create it with the correct key

					logger.Info(fmt.Sprintf("Secret with ID [id=%s] has changed key from [%s] to [%s]. Deleting and re-creating secret", managedSecretId, managedSecretKey, existingSecret.SecretKey))

					deletedSecret, err := kmsClient.Secrets().Delete(kmsSdk.DeleteSecretOptions{
						SecretKey:   existingSecret.SecretKey,
						ProjectID:   destination.ProjectID,
						Environment: destination.EnvironmentSlug,
						SecretPath:  destination.SecretsPath,
					})

					if err != nil {
						secretsFailedToReplaceById = append(secretsFailedToReplaceById, managedSecretKey)
						logger.Info(fmt.Sprintf("unable to delete secret [key=%s] [err=%s]", managedSecretKey, err))
						continue
					}

					createdSecret, err := kmsClient.Secrets().Create(kmsSdk.CreateSecretOptions{
						SecretKey:   managedSecretKey,
						SecretValue: existingSecret.SecretValue,
						ProjectID:   destination.ProjectID,
						Environment: destination.EnvironmentSlug,
						SecretPath:  destination.SecretsPath,
					})

					if err != nil {
						secretsFailedToReplaceById = append(secretsFailedToReplaceById, managedSecretKey)
						logger.Info(fmt.Sprintf("unable to create secret [key=%s] [err=%s]", managedSecretKey, err))
						continue
					}

					delete(kmsPushSecret.Status.ManagedSecrets, deletedSecret.ID)
					kmsPushSecret.Status.ManagedSecrets[createdSecret.ID] = managedSecretKey
				}

			}
		}

		// We need to check if any of the secrets have been removed in the new kube secret
		for _, managedSecretKey := range kmsPushSecret.Status.ManagedSecrets {

			if _, ok := processedSecrets[managedSecretKey]; !ok {

				// Secret has been removed, verify that the secret is managed by the operator
				if getExistingSecretByKey(managedSecretKey) != nil {
					logger.Info(fmt.Sprintf("Secret with key [key=%s] has been removed from the kube secret. Deleting secret from KMS", managedSecretKey))

					deletedSecret, err := kmsClient.Secrets().Delete(kmsSdk.DeleteSecretOptions{
						SecretKey:   managedSecretKey,
						ProjectID:   destination.ProjectID,
						Environment: destination.EnvironmentSlug,
						SecretPath:  destination.SecretsPath,
					})

					if err != nil {
						secretsFailedToDelete = append(secretsFailedToDelete, managedSecretKey)
						logger.Info(fmt.Sprintf("unable to delete secret [key=%s] [err=%s]", managedSecretKey, err))
						continue
					}

					delete(kmsPushSecret.Status.ManagedSecrets, deletedSecret.ID)
				}
			}
		}

		// We need to check if any new secrets have been added in the kube secret
		for currentSecretKey := range processedSecrets {

			if exists := getExistingSecretByKey(currentSecretKey); exists == nil {

				// Some secrets has been added, verify that the secret that has been added is not already managed by the operator
				if _, ok := kmsPushSecret.Status.ManagedSecrets[currentSecretKey]; !ok {

					// Secret was not managed by the operator, lets add it
					logger.Info(fmt.Sprintf("Secret with key [key=%s] has been added to the kube secret. Creating secret in KMS", currentSecretKey))

					createdSecret, err := kmsClient.Secrets().Create(kmsSdk.CreateSecretOptions{
						SecretKey:   currentSecretKey,
						SecretValue: processedSecrets[currentSecretKey],
						ProjectID:   destination.ProjectID,
						Environment: destination.EnvironmentSlug,
						SecretPath:  destination.SecretsPath,
					})

					if err != nil {
						secretsFailedToCreate = append(secretsFailedToCreate, currentSecretKey)
						logger.Info(fmt.Sprintf("unable to create secret [key=%s] [err=%s]", currentSecretKey, err))
						continue
					}

					kmsPushSecret.Status.ManagedSecrets[createdSecret.ID] = currentSecretKey
				}
			} else {
				if updatePolicy == string(constants.PUSH_SECRET_REPLACE_POLICY_ENABLED) {

					existingSecret := getExistingSecretByKey(currentSecretKey)

					if existingSecret != nil && existingSecret.SecretValue != processedSecrets[currentSecretKey] {
						logger.Info(fmt.Sprintf("Secret with key [key=%s] has changed value. Updating secret in KMS", currentSecretKey))

						updatedSecret, err := kmsClient.Secrets().Update(kmsSdk.UpdateSecretOptions{
							SecretKey:      currentSecretKey,
							NewSecretValue: processedSecrets[currentSecretKey],
							ProjectID:      destination.ProjectID,
							Environment:    destination.EnvironmentSlug,
							SecretPath:     destination.SecretsPath,
						})

						if err != nil {
							secretsFailedToUpdate = append(secretsFailedToUpdate, currentSecretKey)
							logger.Info(fmt.Sprintf("unable to update secret [key=%s] [err=%s]", currentSecretKey, err))
							continue
						}

						updateExistingSecretByKey(currentSecretKey, processedSecrets[currentSecretKey])
						kmsPushSecret.Status.ManagedSecrets[updatedSecret.ID] = currentSecretKey
					}
				}
			}
		}

		// Check if any of the existing secrets values have changed
		for secretKey, secretValue := range processedSecrets {

			existingSecret := getExistingSecretByKey(secretKey)

			if existingSecret != nil {

				_, managedByOperator := kmsPushSecret.Status.ManagedSecrets[existingSecret.ID]

				if secretValue != existingSecret.SecretValue {

					if managedByOperator || updatePolicy == string(constants.PUSH_SECRET_REPLACE_POLICY_ENABLED) {
						logger.Info(fmt.Sprintf("Secret with key [key=%s] has changed value. Updating secret in KMS", secretKey))

						updatedSecret, err := kmsClient.Secrets().Update(kmsSdk.UpdateSecretOptions{
							SecretKey:      secretKey,
							NewSecretValue: secretValue,
							ProjectID:      destination.ProjectID,
							Environment:    destination.EnvironmentSlug,
							SecretPath:     destination.SecretsPath,
						})

						if err != nil {
							secretsFailedToUpdate = append(secretsFailedToUpdate, secretKey)
							logger.Info(fmt.Sprintf("unable to update secret [key=%s] [err=%s]", secretKey, err))
							continue
						}

						kmsPushSecret.Status.ManagedSecrets[updatedSecret.ID] = secretKey
					}
				}
			}
		}
	}

	var errorMessage string
	if len(secretsFailedToCreate) > 0 {
		errorMessage = fmt.Sprintf("Failed to create secrets: [%s]", strings.Join(secretsFailedToCreate, ", "))
	} else {
		errorMessage = ""
	}
	r.SetFailedToCreateSecretsStatusCondition(ctx, &kmsPushSecret, fmt.Sprintf("Failed to create secrets: [%s]", errorMessage))

	if len(secretsFailedToUpdate) > 0 {
		errorMessage = fmt.Sprintf("Failed to update secrets: [%s]", strings.Join(secretsFailedToUpdate, ", "))
	} else {
		errorMessage = ""
	}
	r.SetFailedToUpdateSecretsStatusCondition(ctx, &kmsPushSecret, fmt.Sprintf("Failed to update secrets: [%s]", errorMessage))

	if len(secretsFailedToDelete) > 0 {
		errorMessage = fmt.Sprintf("Failed to delete secrets: [%s]", strings.Join(secretsFailedToDelete, ", "))
	} else {
		errorMessage = ""
	}
	r.SetFailedToDeleteSecretsStatusCondition(ctx, &kmsPushSecret, errorMessage)

	if len(secretsFailedToReplaceById) > 0 {
		errorMessage = fmt.Sprintf("Failed to replace secrets: [%s]", strings.Join(secretsFailedToReplaceById, ", "))
	} else {
		errorMessage = ""
	}
	r.SetFailedToReplaceSecretsStatusCondition(ctx, &kmsPushSecret, errorMessage)

	// Update the status of the KMSPushSecret
	if err := r.Client.Status().Update(ctx, &kmsPushSecret); err != nil {
		return fmt.Errorf("unable to update status of KMSPushSecret [err=%s]", err)
	}

	return nil

}

func (r *KMSPushSecretReconciler) DeleteManagedSecrets(ctx context.Context, logger logr.Logger, kmsPushSecret v1alpha1.KMSPushSecret) error {
	if kmsPushSecret.Spec.DeletionPolicy != string(constants.PUSH_SECRET_DELETE_POLICY_ENABLED) {
		return nil
	}

	resourceVariables := r.getResourceVariables(kmsPushSecret)
	kmsClient := resourceVariables.KMSClient
	cancelCtx := resourceVariables.CancelCtx
	authDetails := resourceVariables.AuthDetails
	var err error

	if authDetails.AuthStrategy == "" {
		logger.Info("No authentication strategy found. Attempting to authenticate")
		authDetails, err = r.handleAuthentication(ctx, kmsPushSecret, kmsClient)
		r.SetAuthenticatedStatusCondition(ctx, &kmsPushSecret, err)

		if err != nil {
			return fmt.Errorf("unable to authenticate [err=%s]", err)
		}

		r.updateResourceVariables(kmsPushSecret, util.ResourceVariables{
			KMSClient: kmsClient,
			CancelCtx:       cancelCtx,
			AuthDetails:     authDetails,
		})
	}

	destination := kmsPushSecret.Spec.Destination
	existingSecrets, err := resourceVariables.KMSClient.Secrets().List(kmsSdk.ListSecretsOptions{
		ProjectID:      destination.ProjectID,
		Environment:    destination.EnvironmentSlug,
		SecretPath:     destination.SecretsPath,
		IncludeImports: false,
	})

	if err != nil {
		return fmt.Errorf("unable to list secrets [err=%s]", err)
	}

	existingSecretsMappedById := make(map[string]kmsSdk.Secret)
	for _, secret := range existingSecrets {
		existingSecretsMappedById[secret.ID] = secret
	}

	for managedSecretId, managedSecretKey := range kmsPushSecret.Status.ManagedSecrets {

		if _, ok := existingSecretsMappedById[managedSecretId]; ok {
			logger.Info(fmt.Sprintf("Deleting secret with key [key=%s]", managedSecretKey))

			_, err := kmsClient.Secrets().Delete(kmsSdk.DeleteSecretOptions{
				SecretKey:   managedSecretKey,
				ProjectID:   destination.ProjectID,
				Environment: destination.EnvironmentSlug,
				SecretPath:  destination.SecretsPath,
			})

			if err != nil {
				logger.Info(fmt.Sprintf("unable to delete secret [key=%s] [err=%s]", managedSecretKey, err))
				continue
			}
		}

	}

	return nil
}
