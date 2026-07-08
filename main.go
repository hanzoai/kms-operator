package main

import (
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	secretsv1alpha1 "github.com/hanzoai/kms-operator/api/v1alpha1"
	kmsPushSecretController "github.com/hanzoai/kms-operator/controllers/kmspushsecret"
	kmsSecretController "github.com/hanzoai/kms-operator/controllers/kmssecret"
	"github.com/hanzoai/kms-operator/internal/bootstrap"
	"github.com/hanzoai/kms-operator/packages/template"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

// apiWarningToDebug routes Kubernetes API-server warning headers to V(1).
// KMSSecret CRD schema drift makes the server emit an "unknown field spec.X"
// warning on every reconcile of every CR — thousands of lines/min, the
// operator's dominant log volume. Demoting keeps them at --zap-log-level=debug
// while the default (info) stream stays clean. Implements rest.WarningHandler.
type apiWarningToDebug struct{}

func (apiWarningToDebug) HandleWarningHeader(code int, _ string, message string) {
	if code == 299 && message != "" {
		ctrl.Log.WithName("kube-api-warning").V(1).Info(message)
	}
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(secretsv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var namespace string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&namespace, "namespace", "", "Watch KMSSecrets scoped in the provided namespace only")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: false,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	ctrlOpts := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer:          webhook.NewServer(webhook.Options{Port: 9443}),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "cf2b8c44.lux.network",
	}

	if namespace != "" {
		ctrlOpts.Cache.DefaultNamespaces = map[string]cache.Config{
			namespace: {},
		}
	}

	cfg := ctrl.GetConfigOrDie()
	cfg.WarningHandler = apiWarningToDebug{}
	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	template.InitializeTemplateFunctions()

	// kms-consensus-authority reconciler — bootstrap the operator's own
	// service identity, walk per-service mnemonic Secrets, and pull the
	// upstream luxd validator set on the configured TTL. The same
	// instance is wired into the KMSSecret reconciler so a CR addition
	// auto-enrols its consumer's identity within one reconcile tick.
	bootstrapCfg, err := bootstrap.LoadConfigFromEnv()
	if err != nil {
		setupLog.Error(err, "load bootstrap config")
		os.Exit(1)
	}
	authorityRec := bootstrap.NewReconciler(mgr.GetClient(), ctrl.Log, bootstrapCfg, nil)

	if err = (&kmsSecretController.KMSSecretReconciler{
		Client:                   mgr.GetClient(),
		Scheme:                   mgr.GetScheme(),
		BaseLogger:               ctrl.Log,
		IdentityEnsurer:          authorityRec,
		DefaultMnemonicNamespace: bootstrapCfg.DefaultMnemonicNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KMSSecret")
		os.Exit(1)
	}

	if err = (&kmsPushSecretController.KMSPushSecretReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		BaseLogger:        ctrl.Log,
		IsNamespaceScoped: namespace != "",
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KMSPushSecret")
		os.Exit(1)
	}

	if err := mgr.Add(authorityRec); err != nil {
		setupLog.Error(err, "unable to register kms-consensus-authority reconciler")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
