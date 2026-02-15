package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luxfi/kms/k8-operator/api/v1alpha1"
	"github.com/luxfi/kms/k8-operator/packages/api"
	"github.com/luxfi/kms/k8-operator/packages/constants"
	"github.com/luxfi/kms/k8-operator/packages/util"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"

	kmsSdk "github.com/luxfi/kms-go"
	k8Errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *KMSDynamicSecretReconciler) createKMSManagedKubeSecret(ctx context.Context, logger logr.Logger, kmsDynamicSecret v1alpha1.KMSDynamicSecret, versionAnnotationValue string) error {
	secretType := kmsDynamicSecret.Spec.ManagedSecretReference.SecretType

	// copy labels and annotations from KMSSecret CRD
	labels := map[string]string{}
	for k, v := range kmsDynamicSecret.Labels {
		labels[k] = v
	}

	annotations := map[string]string{}
	systemPrefixes := []string{"kubectl.kubernetes.io/", "kubernetes.io/", "k8s.io/", "helm.sh/"}
	for k, v := range kmsDynamicSecret.Annotations {
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

	annotations[constants.SECRET_VERSION_ANNOTATION] = versionAnnotationValue

	// create a new secret as specified by the managed secret spec of CRD
	newKubeSecretInstance := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        kmsDynamicSecret.Spec.ManagedSecretReference.SecretName,
			Namespace:   kmsDynamicSecret.Spec.ManagedSecretReference.SecretNamespace,
			Annotations: annotations,
			Labels:      labels,
		},
		Type: corev1.SecretType(secretType),
	}

	if kmsDynamicSecret.Spec.ManagedSecretReference.CreationPolicy == "Owner" {
		// Set KMSSecret instance as the owner and controller of the managed secret
		err := ctrl.SetControllerReference(&kmsDynamicSecret, newKubeSecretInstance, r.Scheme)
		if err != nil {
			return err
		}
	}

	err := r.Client.Create(ctx, newKubeSecretInstance)
	if err != nil {
		return fmt.Errorf("unable to create the managed Kubernetes secret : %w", err)
	}

	logger.Info(fmt.Sprintf("Successfully created a managed Kubernetes secret. [type: %s]", secretType))
	return nil
}

func (r *KMSDynamicSecretReconciler) handleAuthentication(ctx context.Context, kmsSecret v1alpha1.KMSDynamicSecret, kmsClient kmsSdk.KMSClientInterface) (util.AuthenticationDetails, error) {
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
			Type:   util.SecretCrd.KMS_DYNAMIC_SECRET,
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

func (r *KMSDynamicSecretReconciler) getKMSCaCertificateFromKubeSecret(ctx context.Context, kmsSecret v1alpha1.KMSDynamicSecret) (caCertificate string, err error) {

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

func (r *KMSDynamicSecretReconciler) getResourceVariables(kmsDynamicSecret v1alpha1.KMSDynamicSecret) util.ResourceVariables {

	var resourceVariables util.ResourceVariables

	if _, ok := kmsDynamicSecretsResourceVariablesMap[string(kmsDynamicSecret.UID)]; !ok {

		ctx, cancel := context.WithCancel(context.Background())

		client := kmsSdk.NewKMSClient(ctx, kmsSdk.Config{
			SiteUrl:       api.API_HOST_URL,
			CaCertificate: api.API_CA_CERTIFICATE,
			UserAgent:     api.USER_AGENT_NAME,
		})

		kmsDynamicSecretsResourceVariablesMap[string(kmsDynamicSecret.UID)] = util.ResourceVariables{
			KMSClient: client,
			CancelCtx:       cancel,
			AuthDetails:     util.AuthenticationDetails{},
		}

		resourceVariables = kmsDynamicSecretsResourceVariablesMap[string(kmsDynamicSecret.UID)]

	} else {
		resourceVariables = kmsDynamicSecretsResourceVariablesMap[string(kmsDynamicSecret.UID)]
	}

	return resourceVariables
}

func (r *KMSDynamicSecretReconciler) CreateDynamicSecretLease(ctx context.Context, logger logr.Logger, kmsClient kmsSdk.KMSClientInterface, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, destination *corev1.Secret) error {
	project, err := util.GetProjectByID(kmsClient.Auth().GetAccessToken(), kmsDynamicSecret.Spec.DynamicSecret.ProjectID)
	if err != nil {
		return err
	}

	request := kmsSdk.CreateDynamicSecretLeaseOptions{
		DynamicSecretName: kmsDynamicSecret.Spec.DynamicSecret.SecretName,
		ProjectSlug:       project.Slug,
		SecretPath:        kmsDynamicSecret.Spec.DynamicSecret.SecretPath,
		EnvironmentSlug:   kmsDynamicSecret.Spec.DynamicSecret.EnvironmentSlug,
	}

	if kmsDynamicSecret.Spec.LeaseTTL != "" {
		request.TTL = kmsDynamicSecret.Spec.LeaseTTL
	}

	leaseData, dynamicSecret, lease, err := kmsClient.DynamicSecrets().Leases().Create(request)

	if err != nil {
		return fmt.Errorf("unable to create lease [err=%s]", err)
	}

	newLeaseStatus := &v1alpha1.KMSDynamicSecretLease{
		ID:                lease.Id,
		ExpiresAt:         metav1.NewTime(lease.ExpireAt),
		CreationTimestamp: metav1.NewTime(time.Now()),
		Version:           int64(lease.Version),
	}

	kmsDynamicSecret.Status.DynamicSecretID = dynamicSecret.Id
	kmsDynamicSecret.Status.MaxTTL = dynamicSecret.MaxTTL
	kmsDynamicSecret.Status.Lease = newLeaseStatus

	// write the leaseData to the destination secret
	destinationData := map[string]string{}

	for key, value := range leaseData {
		if strValue, ok := value.(string); ok {
			destinationData[key] = strValue
		} else {
			return fmt.Errorf("unable to convert value to string for key %s", key)
		}
	}

	destination.StringData = destinationData
	destination.Annotations[constants.SECRET_VERSION_ANNOTATION] = fmt.Sprintf("%s-%d", lease.Id, lease.Version)

	if err := r.Client.Update(ctx, destination); err != nil {
		return fmt.Errorf("unable to update destination secret [err=%s]", err)
	}

	logger.Info(fmt.Sprintf("New lease successfully created [leaseId=%s]", lease.Id))
	return nil
}

func (r *KMSDynamicSecretReconciler) RenewDynamicSecretLease(ctx context.Context, logger logr.Logger, kmsClient kmsSdk.KMSClientInterface, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, destination *corev1.Secret) error {
	project, err := util.GetProjectByID(kmsClient.Auth().GetAccessToken(), kmsDynamicSecret.Spec.DynamicSecret.ProjectID)
	if err != nil {
		return err
	}

	request := kmsSdk.RenewDynamicSecretLeaseOptions{
		LeaseId:         kmsDynamicSecret.Status.Lease.ID,
		ProjectSlug:     project.Slug,
		SecretPath:      kmsDynamicSecret.Spec.DynamicSecret.SecretPath,
		EnvironmentSlug: kmsDynamicSecret.Spec.DynamicSecret.EnvironmentSlug,
	}

	if kmsDynamicSecret.Spec.LeaseTTL != "" {
		request.TTL = kmsDynamicSecret.Spec.LeaseTTL
	}

	lease, err := kmsClient.DynamicSecrets().Leases().RenewById(request)

	if err != nil {

		if strings.Contains(err.Error(), "TTL cannot be larger than max ttl") || // Case 1: TTL is larger than the max TTL
			strings.Contains(err.Error(), "Dynamic secret lease with ID") { // Case 2: The lease has already expired and has been deleted
			return constants.ErrInvalidLease
		}

		return fmt.Errorf("unable to renew lease [err=%s]", err)
	}

	kmsDynamicSecret.Status.Lease.ExpiresAt = metav1.NewTime(lease.ExpireAt)

	// update the kmsDynamicSecret status
	if err := r.Client.Status().Update(ctx, kmsDynamicSecret); err != nil {
		return fmt.Errorf("unable to update KMSDynamicSecret status [err=%s]", err)
	}

	logger.Info(fmt.Sprintf("Lease successfully renewed [leaseId=%s]", lease.Id))
	return nil

}

func (r *KMSDynamicSecretReconciler) updateResourceVariables(kmsDynamicSecret v1alpha1.KMSDynamicSecret, resourceVariables util.ResourceVariables) {
	kmsDynamicSecretsResourceVariablesMap[string(kmsDynamicSecret.UID)] = resourceVariables
}

func (r *KMSDynamicSecretReconciler) HandleLeaseRevocation(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret) error {
	if kmsDynamicSecret.Spec.LeaseRevocationPolicy != string(constants.DYNAMIC_SECRET_LEASE_REVOCATION_POLICY_ENABLED) {
		return nil
	}

	resourceVariables := r.getResourceVariables(*kmsDynamicSecret)
	kmsClient := resourceVariables.KMSClient

	logger.Info("Authenticating for lease revocation")
	authDetails, err := r.handleAuthentication(ctx, *kmsDynamicSecret, kmsClient)

	if err != nil {
		return fmt.Errorf("unable to authenticate for lease revocation [err=%s]", err)
	}

	r.updateResourceVariables(*kmsDynamicSecret, util.ResourceVariables{
		KMSClient: kmsClient,
		CancelCtx:       resourceVariables.CancelCtx,
		AuthDetails:     authDetails,
	})

	if kmsDynamicSecret.Status.Lease == nil {
		return nil
	}

	project, err := util.GetProjectByID(kmsClient.Auth().GetAccessToken(), kmsDynamicSecret.Spec.DynamicSecret.ProjectID)

	if err != nil {
		return err
	}

	kmsClient.DynamicSecrets().Leases().DeleteById(kmsSdk.DeleteDynamicSecretLeaseOptions{
		LeaseId:         kmsDynamicSecret.Status.Lease.ID,
		ProjectSlug:     project.Slug,
		SecretPath:      kmsDynamicSecret.Spec.DynamicSecret.SecretPath,
		EnvironmentSlug: kmsDynamicSecret.Spec.DynamicSecret.EnvironmentSlug,
	})

	// update the destination data to remove the lease data
	destination, err := util.GetKubeSecretByNamespacedName(ctx, r.Client, types.NamespacedName{
		Name:      kmsDynamicSecret.Spec.ManagedSecretReference.SecretName,
		Namespace: kmsDynamicSecret.Spec.ManagedSecretReference.SecretNamespace,
	})

	if err != nil {
		return fmt.Errorf("unable to fetch destination secret [err=%s]", err)
	}

	destination.Data = map[string][]byte{}

	if err := r.Client.Update(ctx, destination); err != nil {
		return fmt.Errorf("unable to update destination secret [err=%s]", err)
	}

	logger.Info(fmt.Sprintf("Lease successfully revoked [leaseId=%s]", kmsDynamicSecret.Status.Lease.ID))

	return nil
}

func (r *KMSDynamicSecretReconciler) ReconcileKMSDynamicSecret(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret) (time.Duration, error) {

	resourceVariables := r.getResourceVariables(*kmsDynamicSecret)
	kmsClient := resourceVariables.KMSClient
	cancelCtx := resourceVariables.CancelCtx
	authDetails := resourceVariables.AuthDetails

	defaultNextReconcile := 5 * time.Second
	nextReconcile := defaultNextReconcile

	var err error

	if authDetails.AuthStrategy == "" {
		logger.Info("No authentication strategy found. Attempting to authenticate")
		authDetails, err = r.handleAuthentication(ctx, *kmsDynamicSecret, kmsClient)
		r.SetAuthenticatedConditionStatus(ctx, logger, kmsDynamicSecret, err)

		if err != nil {
			return nextReconcile, fmt.Errorf("unable to authenticate [err=%s]", err)
		}

		r.updateResourceVariables(*kmsDynamicSecret, util.ResourceVariables{
			KMSClient: kmsClient,
			CancelCtx:       cancelCtx,
			AuthDetails:     authDetails,
		})
	}

	destination, err := util.GetKubeSecretByNamespacedName(ctx, r.Client, types.NamespacedName{
		Name:      kmsDynamicSecret.Spec.ManagedSecretReference.SecretName,
		Namespace: kmsDynamicSecret.Spec.ManagedSecretReference.SecretNamespace,
	})

	if err != nil {
		if k8Errors.IsNotFound(err) {

			annotationValue := ""
			if kmsDynamicSecret.Status.Lease != nil {
				annotationValue = fmt.Sprintf("%s-%d", kmsDynamicSecret.Status.Lease.ID, kmsDynamicSecret.Status.Lease.Version)
			}

			r.createKMSManagedKubeSecret(ctx, logger, *kmsDynamicSecret, annotationValue)

			destination, err = util.GetKubeSecretByNamespacedName(ctx, r.Client, types.NamespacedName{
				Name:      kmsDynamicSecret.Spec.ManagedSecretReference.SecretName,
				Namespace: kmsDynamicSecret.Spec.ManagedSecretReference.SecretNamespace,
			})

			if err != nil {
				return nextReconcile, fmt.Errorf("unable to fetch destination secret after creation [err=%s]", err)
			}

		} else {
			return nextReconcile, fmt.Errorf("unable to fetch destination secret")
		}
	}

	if kmsDynamicSecret.Status.Lease == nil {
		err := r.CreateDynamicSecretLease(ctx, logger, kmsClient, kmsDynamicSecret, destination)
		r.SetCreatedLeaseConditionStatus(ctx, logger, kmsDynamicSecret, err)

		return defaultNextReconcile, err // Short requeue after creation
	} else {
		now := time.Now()
		leaseExpiresAt := kmsDynamicSecret.Status.Lease.ExpiresAt.Time

		// Calculate from creation to expiration
		originalLeaseDuration := leaseExpiresAt.Sub(kmsDynamicSecret.Status.Lease.CreationTimestamp.Time)

		// Generate a random percentage between 20% and 30%
		jitterPercentage := 20 + r.Random.Intn(11) // Random int from 0 to 10, then add 20
		renewalThreshold := originalLeaseDuration * time.Duration(jitterPercentage) / 100
		timeUntilExpiration := time.Until(leaseExpiresAt)

		nextReconcile = timeUntilExpiration / 2

		// Max TTL
		if kmsDynamicSecret.Status.MaxTTL != "" {
			maxTTLDuration, err := util.ConvertIntervalToDuration(&kmsDynamicSecret.Status.MaxTTL)
			if err != nil {
				return defaultNextReconcile, fmt.Errorf("unable to parse MaxTTL duration: %w", err)
			}

			// Calculate when this dynamic secret will hit its max TTL
			maxTTLExpirationTime := kmsDynamicSecret.Status.Lease.CreationTimestamp.Add(maxTTLDuration)

			// Calculate remaining time until max TTL
			timeUntilMaxTTL := maxTTLExpirationTime.Sub(now)
			maxTTLThreshold := maxTTLDuration * 40 / 100

			// If we have less than 40% of max TTL remaining or have exceeded it, create new lease
			if timeUntilMaxTTL <= maxTTLThreshold || now.After(maxTTLExpirationTime) {
				logger.Info(fmt.Sprintf("Approaching or exceeded max TTL [timeUntilMaxTTL=%v] [maxTTLThreshold=%v], creating new lease...",
					timeUntilMaxTTL,
					maxTTLThreshold))

				err := r.CreateDynamicSecretLease(ctx, logger, kmsClient, kmsDynamicSecret, destination)
				r.SetCreatedLeaseConditionStatus(ctx, logger, kmsDynamicSecret, err)
				return defaultNextReconcile, err // Short requeue after creation
			}
		}

		// Fail-safe: If the lease has expired we create a new dynamic secret directly.
		if now.After(leaseExpiresAt) {
			logger.Info("Lease has expired, creating new lease...")
			err = r.CreateDynamicSecretLease(ctx, logger, kmsClient, kmsDynamicSecret, destination)
			r.SetCreatedLeaseConditionStatus(ctx, logger, kmsDynamicSecret, err)
			return defaultNextReconcile, err // Short requeue after creation
		}

		if timeUntilExpiration < renewalThreshold || timeUntilExpiration < 30*time.Second {
			logger.Info(fmt.Sprintf("Lease renewal needed [leaseId=%s] [timeUntilExpiration=%v] [threshold=%v]",
				kmsDynamicSecret.Status.Lease.ID,
				timeUntilExpiration,
				renewalThreshold))

			err = r.RenewDynamicSecretLease(ctx, logger, kmsClient, kmsDynamicSecret, destination)
			r.SetLeaseRenewalConditionStatus(ctx, logger, kmsDynamicSecret, err)

			if err == constants.ErrInvalidLease {
				logger.Info("Failed to renew expired lease, creating new lease...")
				err = r.CreateDynamicSecretLease(ctx, logger, kmsClient, kmsDynamicSecret, destination)
				r.SetCreatedLeaseConditionStatus(ctx, logger, kmsDynamicSecret, err)
			}
			return defaultNextReconcile, err // Short requeue after renewal/creation

		} else {
			logger.Info(fmt.Sprintf("Lease renewal not needed yet [leaseId=%s] [timeUntilExpiration=%v] [threshold=%v]",
				kmsDynamicSecret.Status.Lease.ID,
				timeUntilExpiration,
				renewalThreshold))
		}

		// Small buffer (20% of the calculated time) to ensure we don't cut it too close
		nextReconcile = nextReconcile * 8 / 10

		// Minimum and maximum bounds for the reconcile interval (5 min max, 5 min minimum)
		nextReconcile = max(5*time.Second, min(nextReconcile, 5*time.Minute))
	}

	if err := r.Client.Status().Update(ctx, kmsDynamicSecret); err != nil {
		return nextReconcile, fmt.Errorf("unable to update KMSDynamicSecret status [err=%s]", err)
	}

	return nextReconcile, nil
}
