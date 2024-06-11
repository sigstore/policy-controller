// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trustroot

import (
	"context"
	"time"

	"k8s.io/client-go/tools/cache"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/logging"

	pkgreconciler "knative.dev/pkg/reconciler"
	"knative.dev/pkg/system"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	trustrootinformer "github.com/sigstore/policy-controller/pkg/client/injection/informers/policy/v1alpha1/trustroot"
	trustrootreconciler "github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/trustroot"
	cminformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/configmap"
)

// This is what the default finalizer name is, but make it explicit so we can
// use it in tests as well.
const FinalizerName = "trustroots.policy.sigstore.dev"

type trustrootResyncPeriodKey struct{}

// NewController creates a Reconciler and returns the result of NewImpl.
func NewController(
	ctx context.Context,
	_ configmap.Watcher,
) *controller.Impl {
	trustrootInformer := trustrootinformer.Get(ctx)
	configMapInformer := cminformer.Get(ctx)

	r := &Reconciler{
		configmaplister: configMapInformer.Lister(),
		kubeclient:      kubeclient.Get(ctx),
	}
	impl := trustrootreconciler.NewImpl(ctx, r, func(impl *controller.Impl) controller.Options {
		return controller.Options{FinalizerName: FinalizerName}
	})

	if _, err := trustrootInformer.Informer().AddEventHandler(controller.HandleAll(impl.Enqueue)); err != nil {
		logging.FromContext(ctx).Warnf("Failed trustrootInformer AddEventHandler() %v", err)
	}

	// When the underlying ConfigMap changes,perform a global resync on
	// TrustRoot to make sure their state is correctly reflected
	// in the ConfigMap. This is admittedly a bit heavy handed, but I don't
	// really see a way around it, since if something is wrong with the
	// ConfigMap but there are no changes to the TrustRoot, it needs
	// to be synced.
	grCb := func(obj interface{}) {
		logging.FromContext(ctx).Info("Doing a global resync on TrustRoot due to ConfigMap changing or resync period.")
		impl.GlobalResync(trustrootInformer.Informer())
	}
	// Resync on only ConfigMap changes that pertain to the one I care about.
	// We could also fetch/construct the store and use CM watcher for it, but
	// since we need a lister for it anyways in the reconciler, just set up
	// the watch here.
	if _, err := configMapInformer.Informer().AddEventHandlerWithResyncPeriod(cache.FilteringResourceEventHandler{
		FilterFunc: pkgreconciler.ChainFilterFuncs(
			pkgreconciler.NamespaceFilterFunc(system.Namespace()),
			pkgreconciler.NameFilterFunc(config.SigstoreKeysConfigName)),
		Handler: controller.HandleAll(grCb),
	}, FromContextOrDefaults(ctx)); err != nil {
		logging.FromContext(ctx).Warnf("Failed configMapInformer AddEventHandlerWithResyncPeriod() %v", err)
	}
	return impl
}

func ToContext(ctx context.Context, duration time.Duration) context.Context {
	return context.WithValue(ctx, trustrootResyncPeriodKey{}, duration)
}

// FromContextOrDefaults returns a stored trustrootResyncPeriod if attached.
// If not found, it returns a default duration
func FromContextOrDefaults(ctx context.Context) time.Duration {
	x, ok := ctx.Value(trustrootResyncPeriodKey{}).(time.Duration)
	if ok {
		return x
	}
	return controller.DefaultResyncPeriod
}
