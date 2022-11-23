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

package v1alpha1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/sigstore/policy-controller/pkg/tuf"

	"knative.dev/pkg/apis"
	"knative.dev/pkg/logging"
)

// Validate implements apis.Validatable
func (c *TrustRoot) Validate(ctx context.Context) *apis.FieldError {
	return c.Spec.Validate(ctx).ViaField("spec")
}

func (spec *TrustRootSpec) Validate(ctx context.Context) (errors *apis.FieldError) {
	if spec.Repository == nil && spec.Remote == nil && spec.SigstoreKeys == nil {
		return apis.ErrMissingOneOf("repository", "remote", "sigstoreKeys")
	}
	if spec.Repository != nil {
		if spec.Remote != nil || spec.SigstoreKeys != nil {
			return apis.ErrMultipleOneOf("repository", "remote", "sigstoreKeys")
		}
		return spec.Repository.Validate(ctx).ViaField("repository")
	}
	if spec.Remote != nil {
		if spec.Repository != nil || spec.SigstoreKeys != nil {
			return apis.ErrMultipleOneOf("repository", "remote", "sigstoreKeys")
		}
		return spec.Remote.Validate(ctx).ViaField("remote")
	}
	if spec.SigstoreKeys != nil {
		if spec.Remote != nil || spec.Repository != nil {
			return apis.ErrMultipleOneOf("repository", "remote", "sigstoreKeys")
		}
		return spec.SigstoreKeys.Validate(ctx).ViaField("sigstoreKeys")
	}
	return
}

func (repo *Repository) Validate(ctx context.Context) (errors *apis.FieldError) {
	if repo.Targets == "" {
		errors = errors.Also(apis.ErrMissingField("targets"))
	}

	errors = errors.Also(ValidateRoot(ctx, repo.Root))

	if len(repo.MirrorFS) == 0 {
		errors = errors.Also(apis.ErrMissingField("repository"))
	} else {
		r, err := base64.StdEncoding.DecodeString(string(repo.MirrorFS))
		if err != nil {
			errors = errors.Also(apis.ErrInvalidValue("failed to base64 decode", "mirrorFS", err.Error()))
		} else {
			// Validte that we can uncompress the TUF root.
			fs, err := tuf.UncompressMemFS(bytes.NewReader(r))
			if err != nil {
				errors = errors.Also(apis.ErrInvalidValue("failed to uncompress", "mirrorFS", err.Error()))
			}

			// TODO(vaikas): Do more validation with the FS here.
			logging.FromContext(ctx).Infof("FS uncompressed ok: %+v", fs)
		}
	}
	return
}

func (remote *Remote) Validate(ctx context.Context) (errors *apis.FieldError) {
	if remote.Mirror.String() == "" {
		errors = errors.Also(apis.ErrMissingField("mirror"))
	}
	errors = errors.Also(ValidateRoot(ctx, remote.Root))
	return
}

func (sigstoreKeys *SigstoreKeys) Validate(ctx context.Context) (errors *apis.FieldError) {
	if len(sigstoreKeys.CertificateAuthority) == 0 {
		errors = errors.Also(apis.ErrMissingField("certificateAuthority"))
	} else {
		for i, ca := range sigstoreKeys.CertificateAuthority {
			errors = ValidateCertificateAuthority(ctx, ca).ViaFieldIndex("certificateAuthority", i)
		}
	}

	if len(sigstoreKeys.TimeStampAuthorities) == 0 {
		errors = errors.Also(apis.ErrMissingField("timestampAuthorities"))
	} else {
		for i, ca := range sigstoreKeys.TimeStampAuthorities {
			errors = ValidateCertificateAuthority(ctx, ca).ViaFieldIndex("timestampAuthorities", i)
		}
	}
	return
}

func ValidateRoot(ctx context.Context, rootJSON string) *apis.FieldError {
	if rootJSON == "" {
		return apis.ErrMissingField("root")
	}
	r, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		return apis.ErrInvalidValue("failed to base64 decode", "mirrorFS", err.Error())
	}
	// TODO(vaikas): Tighten this validation to check for proper shape.
	var root map[string]interface{}
	if err := json.Unmarshal(r, &root); err != nil {
		return apis.ErrInvalidValue("failed to unmarshal", "root", err.Error())
	}
	return nil
}

func ValidateCertificateAuthority(ctx context.Context, ca CertificateAuthority) (errors *apis.FieldError) {
	errors = errors.Also(ValidateDistinguishedName(ctx, ca.Subject)).ViaField("subject")
	if ca.URI.String() == "" {
		errors = errors.Also(apis.ErrMissingField("uri"))
	}
	if len(ca.CertChain) == 0 {
		errors = errors.Also(apis.ErrMissingField("subject"))
	}
	// TODO: Validate the certchain more thorougly.
	return
}

func ValidateDistinguishedName(ctx context.Context, dn DistinguishedName) (errors *apis.FieldError) {
	if dn.Organization == "" {
		errors = errors.Also(apis.ErrMissingField("organization"))
	}
	if dn.CommonName == "" {
		errors = errors.Also(apis.ErrMissingField("commonName"))
	}
	return
}

func ValidateTransparencyLogInstance(ctx context.Context, tli TransparencyLogInstance) (errors *apis.FieldError) {
	if tli.BaseURL.String() == "" {
		errors = errors.Also(apis.ErrMissingField("baseURL"))
	}
	if tli.HashAlgorithm == "" {
		errors = errors.Also(apis.ErrMissingField("hashAlgorithm"))
	}
	if len(tli.PublicKey) == 0 {
		errors = errors.Also(apis.ErrMissingField("publicKey"))
	}
	if tli.LogID == "" {
		errors = errors.Also(apis.ErrMissingField("logID"))
	}
	return
}
