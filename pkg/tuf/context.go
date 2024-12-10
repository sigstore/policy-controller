//
// Copyright 2024 The Sigstore Authors.
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

package tuf

import (
	"context"
	"time"

	"knative.dev/pkg/controller"
)

type trustrootResyncPeriodKey struct{}

// ToContext returns a context that includes a key trustrootResyncPeriod
// set to the included duration
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
