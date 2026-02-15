package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/go-logr/logr"
	secretsv1alpha1 "github.com/luxfi/kms/k8-operator/api/v1alpha1"
	"github.com/luxfi/kms/k8-operator/packages/api"
	"github.com/luxfi/kms/k8-operator/packages/constants"
	controllerhelpers "github.com/luxfi/kms/k8-operator/packages/controllerhelpers"
	"github.com/luxfi/kms/k8-operator/packages/util"
)

// KMSDynamicSecretReconciler reconciles a KMSDynamicSecret object
type KMSDynamicSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	BaseLogger logr.Logger
	Random     *rand.Rand
}

var kmsDynamicSecretsResourceVariablesMap map[string]util.ResourceVariables = make(map[string]util.ResourceVariables)

func (r *KMSDynamicSecretReconciler) GetLogger(req ctrl.Request) logr.Logger {
	return r.BaseLogger.WithValues("kmsdynamicsecret", req.NamespacedName)
}

// +kubebuilder:rbac:groups=secrets.lux.network,resources=kmsdynamicsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.lux.network,resources=kmsdynamicsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.lux.network,resources=kmsdynamicsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=list;watch;get;update
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list
//+kubebuilder:rbac:groups="authentication.k8s.io",resources=tokenreviews,verbs=create
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

func (r *KMSDynamicSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := r.GetLogger(req)

	var kmsDynamicSecretCRD secretsv1alpha1.KMSDynamicSecret
	requeueTime := time.Second * 5

	err := r.Get(ctx, req.NamespacedName, &kmsDynamicSecretCRD)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("KMS Dynamic Secret CRD not found")
			return ctrl.Result{
				Requeue: false,
			}, nil
		} else {
			logger.Error(err, "Unable to fetch KMS Dynamic Secret CRD from cluster")
			return ctrl.Result{
				RequeueAfter: requeueTime,
			}, nil
		}
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(&kmsDynamicSecretCRD, constants.KMS_DYNAMIC_SECRET_FINALIZER_NAME) {
		controllerutil.AddFinalizer(&kmsDynamicSecretCRD, constants.KMS_DYNAMIC_SECRET_FINALIZER_NAME)
		if err := r.Update(ctx, &kmsDynamicSecretCRD); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Check if it's being deleted
	if !kmsDynamicSecretCRD.DeletionTimestamp.IsZero() {
		logger.Info("Handling deletion of KMSDynamicSecret")
		if controllerutil.ContainsFinalizer(&kmsDynamicSecretCRD, constants.KMS_DYNAMIC_SECRET_FINALIZER_NAME) {
			// We remove finalizers before running deletion logic to be completely safe from stuck resources
			kmsDynamicSecretCRD.ObjectMeta.Finalizers = []string{}
			if err := r.Update(ctx, &kmsDynamicSecretCRD); err != nil {
				logger.Error(err, fmt.Sprintf("Error removing finalizers from KMSDynamicSecret %s", kmsDynamicSecretCRD.Name))
				return ctrl.Result{}, err
			}

			err := r.HandleLeaseRevocation(ctx, logger, &kmsDynamicSecretCRD)

			if kmsDynamicSecretsResourceVariablesMap != nil {
				if rv, ok := kmsDynamicSecretsResourceVariablesMap[string(kmsDynamicSecretCRD.GetUID())]; ok {
					rv.CancelCtx()
					delete(kmsDynamicSecretsResourceVariablesMap, string(kmsDynamicSecretCRD.GetUID()))
				}
			}

			if err != nil {
				return ctrl.Result{}, err // Even if this fails, we still want to delete the CRD
			}

		}
		return ctrl.Result{}, nil
	}

	// Get modified/default config
	kmsConfig, err := controllerhelpers.GetKMSConfigMap(ctx, r.Client)
	if err != nil {
		logger.Error(err, fmt.Sprintf("unable to fetch kms-config. Will requeue after [requeueTime=%v]", requeueTime))
		return ctrl.Result{
			RequeueAfter: requeueTime,
		}, nil
	}

	if kmsDynamicSecretCRD.Spec.HostAPI == "" {
		api.API_HOST_URL = kmsConfig["hostAPI"]
	} else {
		api.API_HOST_URL = util.AppendAPIEndpoint(kmsDynamicSecretCRD.Spec.HostAPI)
	}

	if kmsDynamicSecretCRD.Spec.TLS.CaRef.SecretName != "" {
		api.API_CA_CERTIFICATE, err = r.getKMSCaCertificateFromKubeSecret(ctx, kmsDynamicSecretCRD)
		if err != nil {
			logger.Error(err, fmt.Sprintf("unable to fetch CA certificate. Will requeue after [requeueTime=%v]", requeueTime))
			return ctrl.Result{
				RequeueAfter: requeueTime,
			}, nil
		}

		logger.Info("Using custom CA certificate...")
	} else {
		api.API_CA_CERTIFICATE = ""
	}

	nextReconcile, err := r.ReconcileKMSDynamicSecret(ctx, logger, &kmsDynamicSecretCRD)
	r.SetReconcileConditionStatus(ctx, logger, &kmsDynamicSecretCRD, err)

	if err == nil && nextReconcile.Seconds() >= 5 {
		requeueTime = nextReconcile
	}

	if err != nil {
		logger.Error(err, fmt.Sprintf("unable to reconcile KMS Push Secret. Will requeue after [requeueTime=%v]", requeueTime))
		return ctrl.Result{
			RequeueAfter: requeueTime,
		}, nil
	}

	numDeployments, err := controllerhelpers.ReconcileDeploymentsWithManagedSecrets(ctx, r.Client, logger, kmsDynamicSecretCRD.Spec.ManagedSecretReference)
	r.SetReconcileAutoRedeploymentConditionStatus(ctx, logger, &kmsDynamicSecretCRD, numDeployments, err)

	if err != nil {
		logger.Error(err, fmt.Sprintf("unable to reconcile auto redeployment. Will requeue after [requeueTime=%v]", requeueTime))
		return ctrl.Result{
			RequeueAfter: requeueTime,
		}, nil
	}

	// Sync again after the specified time
	logger.Info(fmt.Sprintf("Next reconciliation in [requeueTime=%v]", requeueTime))
	return ctrl.Result{
		RequeueAfter: requeueTime,
	}, nil
}

func (r *KMSDynamicSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Custom predicate that allows both spec changes and deletions
	specChangeOrDelete := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only reconcile if spec/generation changed

			isSpecOrGenerationChange := e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()

			if isSpecOrGenerationChange {
				if kmsDynamicSecretsResourceVariablesMap != nil {
					if rv, ok := kmsDynamicSecretsResourceVariablesMap[string(e.ObjectNew.GetUID())]; ok {
						rv.CancelCtx()
						delete(kmsDynamicSecretsResourceVariablesMap, string(e.ObjectNew.GetUID()))
					}
				}
			}

			return isSpecOrGenerationChange
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Always reconcile on deletion

			if kmsDynamicSecretsResourceVariablesMap != nil {
				if rv, ok := kmsDynamicSecretsResourceVariablesMap[string(e.Object.GetUID())]; ok {
					rv.CancelCtx()
					delete(kmsDynamicSecretsResourceVariablesMap, string(e.Object.GetUID()))
				}
			}

			return true
		},
		CreateFunc: func(e event.CreateEvent) bool {
			// Reconcile on creation
			return true
		},
		GenericFunc: func(e event.GenericEvent) bool {
			// Ignore generic events
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KMSDynamicSecret{}, builder.WithPredicates(
			specChangeOrDelete,
		)).
		Complete(r)
}
