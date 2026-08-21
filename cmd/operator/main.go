// Command operator is the CanarySting Kubernetes operator (controller-runtime).
//
// M1 skeleton: it manages the DeceptionPolicy CRD and validates it, reporting the
// result in each policy's status. It plants NO decoys and takes NO destructive
// cluster action — decoy seeding is wired in the canary milestone (M2). canaryctl
// remains the human operator CLI alongside this binary. Prototype (M1 slice 2).
package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	deceptionv1alpha1 "github.com/canarysting/canarysting/internal/operator/api/v1alpha1"
	"github.com/canarysting/canarysting/internal/operator/controller"
)

func main() {
	var metricsAddr, probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "metrics endpoint bind address; 0 disables it")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "health/readiness probe bind address")
	zapOpts := zap.Options{Development: true}
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))
	setup := ctrl.Log.WithName("setup")

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(deceptionv1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		setup.Error(err, "unable to build manager")
		os.Exit(1)
	}

	if err := (&controller.DeceptionPolicyReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		KnownDecoys: knownDecoys(),
	}).SetupWithManager(mgr); err != nil {
		setup.Error(err, "unable to set up the DeceptionPolicy controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setup.Error(err, "unable to add healthz check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setup.Error(err, "unable to add readyz check")
		os.Exit(1)
	}

	setup.Info("starting operator", "note", "M1 skeleton — validates DeceptionPolicy, plants no decoys")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setup.Error(err, "manager exited with error")
		os.Exit(1)
	}
}

// knownDecoys returns the set of valid decoy type names from the canary catalog,
// so the CRD's decoy Types are validated against the real catalog rather than a
// hardcoded list.
func knownDecoys() map[string]bool {
	out := make(map[string]bool)
	for _, t := range catalog.Default().Types() {
		out[string(t)] = true
	}
	return out
}
