package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/luxfi/kms/k8-operator/api/v1alpha1"
	"github.com/luxfi/kms/k8-operator/packages/util"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *KMSSecretReconciler) SetReadyToSyncSecretsConditions(ctx context.Context, logger logr.Logger, kmsSecret *v1alpha1.KMSSecret, secretsCount int, errorToConditionOn error) {
	if kmsSecret.Status.Conditions == nil {
		kmsSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn != nil {
		meta.SetStatusCondition(&kmsSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.lux.network/ReadyToSyncSecrets",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: fmt.Sprintf("Failed to sync secrets. This can be caused by invalid access token or an invalid API host that is set. Error: %v", errorToConditionOn),
		})

		meta.SetStatusCondition(&kmsSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.lux.network/AutoRedeployReady",
			Status:  metav1.ConditionFalse,
			Reason:  "Stopped",
			Message: fmt.Sprintf("Auto redeployment has been stopped because the operator failed to sync secrets. Error: %v", errorToConditionOn),
		})
	} else {
		meta.SetStatusCondition(&kmsSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.lux.network/ReadyToSyncSecrets",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: fmt.Sprintf("KMS controller has started syncing your secrets. Last reconcile synced %d secrets", secretsCount),
		})
	}

	err := r.Client.Status().Update(ctx, kmsSecret)
	if err != nil {
		logger.Error(err, "Could not set condition for ReadyToSyncSecrets")
	}
}

func (r *KMSSecretReconciler) SetKMSTokenLoadCondition(ctx context.Context, logger logr.Logger, kmsSecret *v1alpha1.KMSSecret, authStrategy util.AuthStrategyType, errorToConditionOn error) {
	if kmsSecret.Status.Conditions == nil {
		kmsSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn == nil {
		meta.SetStatusCondition(&kmsSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.lux.network/LoadedKMSToken",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: fmt.Sprintf("KMS controller has loaded the KMS token in provided Kubernetes secret, using %v authentication strategy", authStrategy),
		})
	} else {
		meta.SetStatusCondition(&kmsSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.lux.network/LoadedKMSToken",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: fmt.Sprintf("Failed to load KMS Token from the provided Kubernetes secret because: %v", errorToConditionOn),
		})
	}

	err := r.Client.Status().Update(ctx, kmsSecret)
	if err != nil {
		logger.Error(err, "Could not set condition for LoadedKMSToken")
	}
}

func (r *KMSSecretReconciler) SetKMSAutoRedeploymentReady(ctx context.Context, logger logr.Logger, kmsSecret *v1alpha1.KMSSecret, numDeployments int, errorToConditionOn error) {
	if kmsSecret.Status.Conditions == nil {
		kmsSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn == nil {
		meta.SetStatusCondition(&kmsSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.lux.network/AutoRedeployReady",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: fmt.Sprintf("KMS has found %v deployments which are ready to be auto redeployed when secrets change", numDeployments),
		})
	} else {
		meta.SetStatusCondition(&kmsSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.lux.network/AutoRedeployReady",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: fmt.Sprintf("Failed reconcile deployments because: %v", errorToConditionOn),
		})
	}

	err := r.Client.Status().Update(ctx, kmsSecret)
	if err != nil {
		logger.Error(err, "Could not set condition for AutoRedeployReady")
	}
}
