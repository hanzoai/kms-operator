package controllers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"
	secretsv1alpha1 "github.com/luxfi/kms/k8-operator/api/v1alpha1"
	"github.com/luxfi/kms/k8-operator/packages/api"
	"github.com/luxfi/kms/k8-operator/packages/constants"
	controllerhelpers "github.com/luxfi/kms/k8-operator/packages/controllerhelpers"
	"github.com/luxfi/kms/k8-operator/packages/util"
)

// KMSSecretReconciler reconciles a KMSSecret object
type KMSPushSecretReconciler struct {
	client.Client
	IsNamespaceScoped bool
	BaseLogger        logr.Logger
	Scheme            *runtime.Scheme
}

var kmsPushSecretResourceVariablesMap map[string]util.ResourceVariables = make(map[string]util.ResourceVariables)

func (r *KMSPushSecretReconciler) GetLogger(req ctrl.Request) logr.Logger {
	return r.BaseLogger.WithValues("kmspushsecret", req.NamespacedName)
}

//+kubebuilder:rbac:groups=secrets.lux.network,resources=kmspushsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.lux.network,resources=kmspushsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.lux.network,resources=kmspushsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=list;watch;get;update
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list
//+kubebuilder:rbac:groups="authentication.k8s.io",resources=tokenreviews,verbs=create
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
//+kubebuilder:rbac:groups=secrets.lux.network,resources=clustergenerators,verbs=get;list;watch;create;update;patch;delete
// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.1/pkg/reconcile

func (r *KMSPushSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := r.GetLogger(req)

	var kmsPushSecretCRD secretsv1alpha1.KMSPushSecret
	requeueTime := time.Minute // seconds

	err := r.Get(ctx, req.NamespacedName, &kmsPushSecretCRD)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("KMS Push Secret CRD not found")
			r.DeleteManagedSecrets(ctx, logger, kmsPushSecretCRD)

			return ctrl.Result{
				Requeue: false,
			}, nil
		} else {
			logger.Error(err, "Unable to fetch KMS Secret CRD from cluster")
			return ctrl.Result{
				RequeueAfter: requeueTime,
			}, nil
		}
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(&kmsPushSecretCRD, constants.KMS_PUSH_SECRET_FINALIZER_NAME) {
		controllerutil.AddFinalizer(&kmsPushSecretCRD, constants.KMS_PUSH_SECRET_FINALIZER_NAME)
		if err := r.Update(ctx, &kmsPushSecretCRD); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Check if it's being deleted
	if !kmsPushSecretCRD.DeletionTimestamp.IsZero() {
		logger.Info("Handling deletion of KMSPushSecret")
		if controllerutil.ContainsFinalizer(&kmsPushSecretCRD, constants.KMS_PUSH_SECRET_FINALIZER_NAME) {
			// We remove finalizers before running deletion logic to be completely safe from stuck resources
			kmsPushSecretCRD.ObjectMeta.Finalizers = []string{}
			if err := r.Update(ctx, &kmsPushSecretCRD); err != nil {
				logger.Error(err, fmt.Sprintf("Error removing finalizers from KMSPushSecret %s", kmsPushSecretCRD.Name))
				return ctrl.Result{}, err
			}

			if err := r.DeleteManagedSecrets(ctx, logger, kmsPushSecretCRD); err != nil {
				return ctrl.Result{}, err // Even if this fails, we still want to delete the CRD
			}

		}
		return ctrl.Result{}, nil
	}

	if kmsPushSecretCRD.Spec.Push.Secret == nil && kmsPushSecretCRD.Spec.Push.Generators == nil {
		logger.Info("No secret or generators found, skipping reconciliation. Please define ")
		return ctrl.Result{}, nil
	}

	duration, err := util.ConvertIntervalToDuration(kmsPushSecretCRD.Spec.ResyncInterval)

	if err != nil {
		// if resyncInterval is nil, we don't want to reconcile automatically
		if kmsPushSecretCRD.Spec.ResyncInterval != nil {
			logger.Error(err, fmt.Sprintf("unable to convert resync interval to duration. Will requeue after [requeueTime=%v]", requeueTime))
			return ctrl.Result{
				RequeueAfter: requeueTime,
			}, nil
		} else {
			logger.Error(err, "unable to convert resync interval to duration")
			return ctrl.Result{}, err
		}
	}

	requeueTime = duration

	if requeueTime != 0 {
		logger.Info(fmt.Sprintf("Manual re-sync interval set. Interval: %v", requeueTime))
	}

	// Check if the resource is already marked for deletion
	if kmsPushSecretCRD.GetDeletionTimestamp() != nil {
		return ctrl.Result{
			Requeue: false,
		}, nil
	}

	// Get modified/default config
	kmsConfig, err := controllerhelpers.GetKMSConfigMap(ctx, r.Client)
	if err != nil {
		if requeueTime != 0 {
			logger.Error(err, fmt.Sprintf("unable to fetch kms-config. Will requeue after [requeueTime=%v]", requeueTime))
			return ctrl.Result{
				RequeueAfter: requeueTime,
			}, nil
		} else {
			logger.Error(err, "unable to fetch kms-config")
			return ctrl.Result{}, err
		}
	}

	if kmsPushSecretCRD.Spec.HostAPI == "" {
		api.API_HOST_URL = kmsConfig["hostAPI"]
	} else {
		api.API_HOST_URL = util.AppendAPIEndpoint(kmsPushSecretCRD.Spec.HostAPI)
	}

	if kmsPushSecretCRD.Spec.TLS.CaRef.SecretName != "" {
		api.API_CA_CERTIFICATE, err = r.getKMSCaCertificateFromKubeSecret(ctx, kmsPushSecretCRD)
		if err != nil {
			if requeueTime != 0 {
				logger.Error(err, fmt.Sprintf("unable to fetch CA certificate. Will requeue after [requeueTime=%v]", requeueTime))
				return ctrl.Result{
					RequeueAfter: requeueTime,
				}, nil
			} else {
				logger.Error(err, "unable to fetch CA certificate")
				return ctrl.Result{}, err
			}
		}

		logger.Info("Using custom CA certificate...")
	} else {
		api.API_CA_CERTIFICATE = ""
	}

	err = r.ReconcileKMSPushSecret(ctx, logger, kmsPushSecretCRD)
	r.SetReconcileStatusCondition(ctx, &kmsPushSecretCRD, err)

	if err != nil {
		if requeueTime != 0 {
			logger.Error(err, fmt.Sprintf("unable to reconcile KMS Push Secret. Will requeue after [requeueTime=%v]", requeueTime))
			return ctrl.Result{
				RequeueAfter: requeueTime,
			}, nil
		} else {
			logger.Error(err, "unable to reconcile KMS Push Secret")
			return ctrl.Result{}, err
		}
	}

	// Sync again after the specified time
	if requeueTime != 0 {
		logger.Info(fmt.Sprintf("Operator will requeue after [%v]", requeueTime))
		return ctrl.Result{
			RequeueAfter: requeueTime,
		}, nil
	} else {
		logger.Info("Operator will reconcile on next spec change")
		return ctrl.Result{}, nil
	}
}

func (r *KMSPushSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Custom predicate that allows both spec changes and deletions
	specChangeOrDelete := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only reconcile if spec/generation changed

			isSpecOrGenerationChange := e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()

			if isSpecOrGenerationChange {
				if kmsPushSecretResourceVariablesMap != nil {
					if rv, ok := kmsPushSecretResourceVariablesMap[string(e.ObjectNew.GetUID())]; ok {
						rv.CancelCtx()
						delete(kmsPushSecretResourceVariablesMap, string(e.ObjectNew.GetUID()))
					}
				}
			}

			return isSpecOrGenerationChange
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Always reconcile on deletion

			if kmsPushSecretResourceVariablesMap != nil {
				if rv, ok := kmsPushSecretResourceVariablesMap[string(e.Object.GetUID())]; ok {
					rv.CancelCtx()
					delete(kmsPushSecretResourceVariablesMap, string(e.Object.GetUID()))
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

	controllerManager := ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KMSPushSecret{}, builder.WithPredicates(
			specChangeOrDelete,
		)).
		Watches(
			&source.Kind{Type: &corev1.Secret{}},
			handler.EnqueueRequestsFromMapFunc(r.findPushSecretsForSecret),
		)

	if !r.IsNamespaceScoped {
		r.BaseLogger.Info("Watching ClusterGenerators for non-namespace scoped operator")
		controllerManager.Watches(
			&source.Kind{Type: &secretsv1alpha1.ClusterGenerator{}},
			handler.EnqueueRequestsFromMapFunc(r.findPushSecretsForClusterGenerator),
		)
	} else {
		r.BaseLogger.Info("Not watching ClusterGenerators for namespace scoped operator")
	}

	return controllerManager.Complete(r)
}

func (r *KMSPushSecretReconciler) findPushSecretsForClusterGenerator(o client.Object) []reconcile.Request {
	ctx := context.Background()
	pushSecrets := &secretsv1alpha1.KMSPushSecretList{}
	if err := r.List(ctx, pushSecrets); err != nil {
		return []reconcile.Request{}
	}

	clusterGenerator, ok := o.(*secretsv1alpha1.ClusterGenerator)
	if !ok {
		return []reconcile.Request{}
	}

	requests := []reconcile.Request{}

	for _, pushSecret := range pushSecrets.Items {
		if pushSecret.Spec.Push.Generators != nil {
			for _, generator := range pushSecret.Spec.Push.Generators {
				if generator.GeneratorRef.Name == clusterGenerator.GetName() {
					requests = append(requests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      pushSecret.GetName(),
							Namespace: pushSecret.GetNamespace(),
						},
					})
					break
				}
			}
		}
	}
	return requests
}

func (r *KMSPushSecretReconciler) findPushSecretsForSecret(o client.Object) []reconcile.Request {
	ctx := context.Background()
	pushSecrets := &secretsv1alpha1.KMSPushSecretList{}
	if err := r.List(ctx, pushSecrets); err != nil {
		return []reconcile.Request{}
	}

	requests := []reconcile.Request{}
	for _, pushSecret := range pushSecrets.Items {
		if pushSecret.Spec.Push.Secret != nil &&
			pushSecret.Spec.Push.Secret.SecretName == o.GetName() &&
			pushSecret.Spec.Push.Secret.SecretNamespace == o.GetNamespace() {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      pushSecret.GetName(),
					Namespace: pushSecret.GetNamespace(),
				},
			})
		}

	}

	return requests
}
