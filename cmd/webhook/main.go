//
// Copyright 2021 The Sigstore Authors.
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

package main

import (
	"context"
	"embed"
	"flag"
	"log"
	"os"
	"path"

	policyduckv1beta1 "github.com/sigstore/policy-controller/pkg/apis/duck/v1beta1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/injection/sharedmain"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/signals"
	"knative.dev/pkg/webhook"
	"knative.dev/pkg/webhook/certificates"
	"knative.dev/pkg/webhook/resourcesemantics"
	"knative.dev/pkg/webhook/resourcesemantics/defaulting"
	"knative.dev/pkg/webhook/resourcesemantics/validation"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/sigstore/pkg/tuf"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
	cwebhook "github.com/sigstore/policy-controller/pkg/webhook"
)

// webhookName holds the name of the validating and mutating webhook
// configuration resources dispatching admission requests to policy-controller.
// It is also the name of the webhook which is injected by the controller
// with the resource types, namespace selectors, CABundle and service path.
// If this changes, you must also change:
//
//	./config/500-webhook-configuration.yaml
//	https://github.com/sigstore/helm-charts/blob/main/charts/policy-controller/templates/webhook/webhook_mutating.yaml
//	https://github.com/sigstore/helm-charts/blob/main/charts/policy-controller/templates/webhook/webhook_validating.yaml
var webhookName = flag.String("webhook-name", "policy.sigstore.dev", "The name of the validating and mutating webhook configurations as well as the webhook name that is automatically configured, if exists, with different rules and client settings setting how the admission requests to be dispatched to policy-controller.")

var tufMirror = flag.String("tuf-mirror", tuf.DefaultRemoteRoot, "Alternate TUF mirror. If left blank, public sigstore one is used")
var tufRoot = flag.String("tuf-root", "", "Alternate TUF root.json. If left blank, public sigstore one is used")

//go:embed tuf/root.json
var content embed.FS

func main() {
	opts := webhook.Options{
		ServiceName: "webhook",
		Port:        8443,
		SecretName:  "webhook-certs",
	}
	ctx := webhook.WithOptions(signals.NewContext(), opts)

	// Allow folks to configure the port the webhook serves on.
	flag.IntVar(&opts.Port, "secure-port", opts.Port, "The port on which to serve HTTPS.")

	flag.Parse()

	// If they provided an alternate TUF root file to use, read it here.
	var tufRootBytes []byte
	var err error
	if *tufRoot != "" {
		tufRootBytes, err = os.ReadFile(*tufRoot)
		if err != nil {
			logging.FromContext(ctx).Panicf("Failed to read alternate TUF root file %s : %v", *tufRoot, err)
		}
	} else {
		// Use embedded and trusted root reducing the amount of call to update it.
		tufRootBytes, err = content.ReadFile(path.Join("tuf", "root.json"))
		if err != nil {
			logging.FromContext(ctx).Panicf("Failed to read embedded TUF root file %s : %v", path.Join("tuf", "root.json"), err)
		}
	}
	logging.FromContext(ctx).Infof("Initializing TUF root from %s => %s", *tufRoot, *tufMirror)
	if err := tuf.Initialize(ctx, *tufMirror, tufRootBytes); err != nil {
		logging.FromContext(ctx).Panicf("Failed to initialize TUF client from %s : %v", *tufRoot, err)
	}

	v := version.GetVersionInfo()
	vJSON, _ := v.JSONString()
	log.Printf("%v", vJSON)
	// This calls flag.Parse()
	sharedmain.MainWithContext(ctx, "policy-controller",
		certificates.NewController,
		NewValidatingAdmissionController,
		NewMutatingAdmissionController,
	)
}

var (
	_ resourcesemantics.SubResourceLimited = (*crdNoStatusUpdatesOrDeletes)(nil)
	_ resourcesemantics.VerbLimited        = (*crdNoStatusUpdatesOrDeletes)(nil)

	_ resourcesemantics.SubResourceLimited = (*crdEphemeralContainers)(nil)
	_ resourcesemantics.VerbLimited        = (*crdEphemeralContainers)(nil)
)

type crdNoStatusUpdatesOrDeletes struct {
	resourcesemantics.GenericCRD
}

type crdEphemeralContainers struct {
	resourcesemantics.GenericCRD
}

func (c *crdNoStatusUpdatesOrDeletes) SupportedSubResources() []string {
	// We do not want any updates that are for status, scale, or anything else.
	return []string{""}
}

func (c *crdEphemeralContainers) SupportedSubResources() []string {
	return []string{"/ephemeralcontainers", ""}
}

func (c *crdNoStatusUpdatesOrDeletes) SupportedVerbs() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
}

func (c *crdEphemeralContainers) SupportedVerbs() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
}

var types = map[schema.GroupVersionKind]resourcesemantics.GenericCRD{
	corev1.SchemeGroupVersion.WithKind("Pod"): &crdEphemeralContainers{GenericCRD: &duckv1.Pod{}},

	appsv1.SchemeGroupVersion.WithKind("ReplicaSet"):  &crdNoStatusUpdatesOrDeletes{GenericCRD: &policyduckv1beta1.PodScalable{}},
	appsv1.SchemeGroupVersion.WithKind("Deployment"):  &crdNoStatusUpdatesOrDeletes{GenericCRD: &policyduckv1beta1.PodScalable{}},
	appsv1.SchemeGroupVersion.WithKind("StatefulSet"): &crdNoStatusUpdatesOrDeletes{GenericCRD: &policyduckv1beta1.PodScalable{}},
	appsv1.SchemeGroupVersion.WithKind("DaemonSet"):   &crdNoStatusUpdatesOrDeletes{GenericCRD: &duckv1.WithPod{}},
	batchv1.SchemeGroupVersion.WithKind("Job"):        &crdNoStatusUpdatesOrDeletes{GenericCRD: &duckv1.WithPod{}},

	batchv1.SchemeGroupVersion.WithKind("CronJob"):      &crdNoStatusUpdatesOrDeletes{GenericCRD: &duckv1.CronJob{}},
	batchv1beta1.SchemeGroupVersion.WithKind("CronJob"): &crdNoStatusUpdatesOrDeletes{GenericCRD: &duckv1.CronJob{}},
}

func NewValidatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	// Decorate contexts with the current state of the config.
	store := config.NewStore(logging.FromContext(ctx).Named("config-store"))
	store.WatchConfigs(cmw)
	policyControllerConfigStore := policycontrollerconfig.NewStore(logging.FromContext(ctx).Named("config-policy-controller"))
	policyControllerConfigStore.WatchConfigs(cmw)

	kc := kubeclient.Get(ctx)
	validator := cwebhook.NewValidator(ctx)

	return validation.NewAdmissionController(ctx,
		// Name of the resource webhook.
		*webhookName,

		// The path on which to serve the webhook.
		"/validations",

		// The resources to validate.
		types,

		// A function that infuses the context passed to Validate/SetDefaults with custom metadata.
		func(ctx context.Context) context.Context {
			ctx = context.WithValue(ctx, kubeclient.Key{}, kc)
			ctx = store.ToContext(ctx)
			ctx = policyControllerConfigStore.ToContext(ctx)
			ctx = policyduckv1beta1.WithPodScalableValidator(ctx, validator.ValidatePodScalable)
			ctx = duckv1.WithPodValidator(ctx, validator.ValidatePod)
			ctx = duckv1.WithPodSpecValidator(ctx, validator.ValidatePodSpecable)
			ctx = duckv1.WithCronJobValidator(ctx, validator.ValidateCronJob)
			return ctx
		},

		// Whether to disallow unknown fields.
		// We pass false because we're using partial schemas.
		false,

		// Extra validating callbacks to be applied to resources.
		nil,
	)
}

func NewMutatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	kc := kubeclient.Get(ctx)
	validator := cwebhook.NewValidator(ctx)

	return defaulting.NewAdmissionController(ctx,
		// Name of the resource webhook.
		*webhookName,

		// The path on which to serve the webhook.
		"/mutations",

		// The resources to validate.
		types,

		// A function that infuses the context passed to Validate/SetDefaults with custom metadata.
		func(ctx context.Context) context.Context {
			ctx = context.WithValue(ctx, kubeclient.Key{}, kc)
			ctx = policyduckv1beta1.WithPodScalableDefaulter(ctx, validator.ResolvePodScalable)
			ctx = duckv1.WithPodDefaulter(ctx, validator.ResolvePod)
			ctx = duckv1.WithPodSpecDefaulter(ctx, validator.ResolvePodSpecable)
			ctx = duckv1.WithCronJobDefaulter(ctx, validator.ResolveCronJob)
			return ctx
		},

		// Whether to disallow unknown fields.
		// We pass false because we're using partial schemas.
		false,
	)
}
