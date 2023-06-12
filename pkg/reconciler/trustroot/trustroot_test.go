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
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"knative.dev/pkg/apis"
	logtesting "knative.dev/pkg/logging/testing"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	fakecosignclient "github.com/sigstore/policy-controller/pkg/client/injection/client/fake"
	"github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/trustroot"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgotesting "k8s.io/client-go/testing"
	fakekubeclient "knative.dev/pkg/client/injection/kube/client/fake"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/system"

	. "github.com/sigstore/policy-controller/pkg/reconciler/testing/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/reconciler/trustroot/resources"
	. "knative.dev/pkg/reconciler/testing"
	_ "knative.dev/pkg/system/testing"
)

const (
	trName   = "test-trustroot"
	testKey  = "test-trustroot"
	tkName2  = "test-trustroot-2"
	testKey2 = "test-trustroot-2"

	resourceVersion = "0123456789"
	uid             = "test-uid"
	uid2            = "test-uid-2"

	// NOTE: To generate these values, I deployed the scaffolding bits on a kind clusters
	// using the setup-kind.sh and setup-scaffolding-from-release.sh scripts.
	// Then I extracted the root.json from the tuf-system secrets 'tuf-root' and 'tuf-secrets'.
	// Finally I extracted the rest of public keys from other secrets (ctlog-public-key, fulcio-pub-key)
	// located in the cluster under the tuf-system namespace.
	ctfePublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW6UV/LgW13DHe71namu5SYPI6ov5
0Yv7BF6K4Mz18TzYc0yaaEV20ZHKvnWrtnRZC2rvQ7RfSIFuXw6BECdMJg==
-----END PUBLIC KEY-----
`
	// This is the LogID for above PublicKey
	ctfeLogID = "c885570b8f5368be85c140915749dac7e7c489be345e60ae7ab1d766cc191f69"

	fulcioCert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`
	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHHzXneDuZ5QS+hqqTWeups5PoR1o
uuxxnnvpqPmTAxb8iZ7Vx8TkFsjE/GUgjLto1uGCYp64XR135exNYjfzMA==
-----END PUBLIC KEY-----
`
	// This is the Rekor LogID constructed from above public key.
	rekorLogID = "7b12eee368e5f2853aebd039b8aee610b7aa165c801be86497fafb159babef05"

	tsaCertChain = `-----BEGIN CERTIFICATE-----
MIIByzCCAXKgAwIBAgIUQ5YYtVEevhGv/lmV5GftZRJvzMswCgYIKoZIzj0EAwIw
MDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0
ZTAeFw0yMzA2MTIwODU1MDlaFw0zMjA2MTIwODU4MDlaMDAxDjAMBgNVBAoTBWxv
Y2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT3yTP8rOPK3m3KF3wexXBRZjqaFX5qAsNnW9rEiENtZ4oz
9j32s5UuBZrJmK6+S1jMisRzck2faVlAV1qMkPJZo2owaDAOBgNVHQ8BAf8EBAMC
B4AwHQYDVR0OBBYEFCRFQ9ohTnIf2x+BFpHg8AFMp4vRMB8GA1UdIwQYMBaAFEFc
c96QOp3HZfI3Q9zAIZStHkC8MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqG
SM49BAMCA0cAMEQCIGy9XdTrKODF0T24OXA405iH85D8peH7MWhrdIzh9C2aAiBc
dblGJLQwe/K0UV0QWm+3v9rHwwdO18Jl5eFYaebxSg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB0jCCAXigAwIBAgIUTOjkgKSn6gvqI21E3DMX6pXW0vUwCgYIKoZIzj0EAwIw
KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjMw
NjEyMDg1MzA5WhcNMzMwNjEyMDg1ODA5WjAwMQ4wDAYDVQQKEwVsb2NhbDEeMBwG
A1UEAxMVVGVzdCBUU0EgSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEnIf4j+rr96W+1QizvQHSDlAPeFXqqxznHDuLJ2CUmRh28GNqKuN9LMXD
PhyTD708S+blcMB42n6iAvJle17mp6N4MHYwDgYDVR0PAQH/BAQDAgEGMBMGA1Ud
JQQMMAoGCCsGAQUFBwMIMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFEFcc96Q
Op3HZfI3Q9zAIZStHkC8MB8GA1UdIwQYMBaAFGtrEQ/gB/LreOIPZkRxiiElKAh0
MAoGCCqGSM49BAMCA0gAMEUCIH0yM/GZTOVQS3mCeaAZ4zgYqZg2D3KhdofuOIlS
JPjuAiEAlGjZcGM3oU8kse7iz3xJjTv+idcGsv4JY74J97NuOUQ=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBlTCCATqgAwIBAgIUXIhIKQDOwcWjpbv6YTFj7+ZY/pswCgYIKoZIzj0EAwIw
KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjMw
NjEyMDg1MzA5WhcNMzMwNjEyMDg1ODA5WjAoMQ4wDAYDVQQKEwVsb2NhbDEWMBQG
A1UEAxMNVGVzdCBUU0EgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ+V
VAEFW80/nfiJKoMcHOrfsgnZ26dX9lORpaxhF0dKL1c/v6StmRc7ukeFM3zASY0/
Y9CQ6QvmeqjnyJyM+gWjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBRraxEP4Afy63jiD2ZEcYohJSgIdDAKBggqhkjOPQQDAgNJ
ADBGAiEAmbvFirwWZ1OkctWKUpUgbhZck3JiFB7EpXwrF9591r0CIQD80uDimXHC
30+HWcL2z4iisBrhPok7OY+4xHlHvpfIuw==
-----END CERTIFICATE-----
`

	// This is the marshalled entry from above keys/certs with fixed values
	// (for ease of testing) for other parts.
	marshalledEntry = `{"certificateAuthorities":[{"subject":{"organization":"fulcio-organization","commonName":"fulcio-common-name"},"uri":"https://fulcio.example.com","certChain":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZ3ekNDQTZ1Z0F3SUJBZ0lJWVNLZHJGSzNxdnd3RFFZSktvWklodmNOQVFFTEJRQXdmakVNTUFvR0ExVUUKQmhNRFZWTkJNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVFlXNGdSbkpoYm1OcApjMk52TVJZd0ZBWURWUVFKRXcwMU5EZ2dUV0Z5YTJWMElGTjBNUTR3REFZRFZRUVJFd1UxTnpJM05ERVpNQmNHCkExVUVDaE1RVEdsdWRYZ2dSbTkxYm1SaGRHbHZiakFlRncweU16QTJNVEl3T0RVM016aGFGdzB5TkRBMk1USXcKT0RVM016aGFNSDR4RERBS0JnTlZCQVlUQTFWVFFURVRNQkVHQTFVRUNCTUtRMkZzYVdadmNtNXBZVEVXTUJRRwpBMVVFQnhNTlUyRnVJRVp5WVc1amFYTmpiekVXTUJRR0ExVUVDUk1OTlRRNElFMWhjbXRsZENCVGRERU9NQXdHCkExVUVFUk1GTlRjeU56UXhHVEFYQmdOVkJBb1RFRXhwYm5WNElFWnZkVzVrWVhScGIyNHdnZ0lpTUEwR0NTcUcKU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRREFYVmduN05MbzJOK1MwVjVPVVA4Rmc5azF5VDYrdCtLMApRSE1Nb2V6MWdINGV5bUNtNVhpcTJicHNMK2RsNnZseWJlWk94TEJxdmxiVVFPUVA3ZGFGVll4MDlYenBqclU4CkVzQkRHSmdnK1VackYreFJIL3FHOEMwOVB1bXlWdVczeE9lSzNiVU9BNTMyb2pWbS9PY3Q2UHFQSSsvMkZmRC8KbVJZRHlpWTZyRDVxTnNkYWZicHNnSGlOWXpCMjRucjFyOUR5K09DK0dEa2NjK2FEQnZ4R2w1dlUrSEQyYTZaUwpGSy8vUHZoSWdLWnNkTi9RL0hEYndYY1BmeThwT3pYRkNhWHJZRFVmMXA4ZzY3MlpVVGJmNlhndWRYYklXYUpHCmxtN3dWekJIM3c2MlEyNkFjd3RwMW5zWEgway83L0M4RFdpVWMxa0NKaFBkdjRwajdMQlBPTXFaYTljdGtJMHAKcmZHRVpaN2szWmpPa1BtVnpqekMrS3VQeWUyRFNJVkpqeFpUeWV1NVJycUJzbHZYUXdObE9VWDVzZXlhb2lKMwpEVllRSmExWmc0c0V1SGJxT0tLMThGNlBUaitBRjNHMmZOelh4eU9Bc3U0SWRBVHhPM0tKdlN3UkliNVpVOUxvCm9vdDdPOGdyM21VcUtxMlZhNmVnaW8zVDZSR1oyKzBZc0UzMm1jRUk1Z0lkd21GdDBsTm5KbkxqVkp3WUxIQjUKbzNSa1k0RzZDMVp4a1AzY0o0WTM4TzFiVGxjb1dFVlk3UWtpZ0V3YnpEcFJTS09VUTlVbnE0Tm84ZUJNeEpmSAowNkhVUUFMc3ZxVGhnZHNHOTYxbUZ4MndvL2NMQ2txUGxoSjdzdjJEOEh6ZTNMeWxEQU0vUEd1eTk5WDlsUjY4CjZFTnVadkZGVFFJREFRQUJvMFV3UXpBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFUQWRCZ05WSFE0RUZnUVVxYThpaTBpQVpYcDhjM3FrZGNZMm9qbnh1T0V3RFFZSktvWklodmNOQVFFTApCUUFEZ2dJQkFBUXF3VVNPdTlvK1B2TzJBaEV0c1lmMmZhMnBJNGtKOW4wemc4QksxNGhvVGxVYk5XMTZGaEs3Cms3cUIzRVNwcmczNGhBQXJGeGJ2TUx5ZGdUQmozQVRVaDhRNGYyVGFEeTJoTlFZTUJFMytLbURCMEdLRUJpaloKdXFCei9ZMVV6aEkvbW52ZzVNdUtjckh0dDVOY2tmVHRyeDk4TXAxZ1Y4RHhZZ3JBRUNmSDh5OU5TWmVtdmhaUgpWQnRqc3Rhd0M0b0ZablJPd1NFUzJzc2JtbVZKa2FTaWh4VVhodWVDaXZtc2xuRFRsNjdaNzc4RFJYaGl5ekF3CmZ0NjVZTUE4QldIWDBHRGJsT1F3QlNyVzJrcEFNcUFLWGpKQmRUaUlVM0syM0hIVCtuaDBsVU1xc3JOaUZtOEUKcTF5a2NhL3VmSEFFNEdXamRINnd0bmZaZG5aT2ZLQkkrOGMrYXhJd0VvUVA3SWplQnN4YWF1MkRhV25CbHFmTwpmMmhEbFlkSmtmTEI0cTZJZEZWK1d2ZmRLYzF4djBML0VzRVRxM1pnVjU1bE1IRE9raVhvTXRVc3hxZTF2VklmCk5VdDdBanVyN3ErNVdYVFkrbHZlYUY5a2Mzd3ZZczBQUkt6YkthRkNITGlnUUcxUUhjNitnOWtXZkREb0NIRkgKT0pGZ2h3OVAyZ0UydERhcDFmZ0FaRU5HaEhRVUMrOWRuNmxVK0huN1AwMFIxWWdWMjJSMjk2WTlhNENZM3k3dAo5U3NzU3pJRWJhdWQ3SkUvMzBLRkd6TUNVQlp3dUtCeU5IZnk5UjlKUkJvRjlUWG1pYjc0ekRQek4xT0NOaFhMCnFNcktjb2cvTFRvd21KYVBKL1drRkx2cGcya0wvTCtXUCt1ZDE4ZTlBSVdwdlRacFhHaVAKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}],"tLogs":[{"baseURL":"https://rekor.example.com","hashAlgorithm":"sha-256","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSEh6WG5lRHVaNVFTK2hxcVRXZXVwczVQb1Ixbwp1dXh4bm52cHFQbVRBeGI4aVo3Vng4VGtGc2pFL0dVZ2pMdG8xdUdDWXA2NFhSMTM1ZXhOWWpmek1BPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"7b12eee368e5f2853aebd039b8aee610b7aa165c801be86497fafb159babef05"}],"ctLogs":[{"baseURL":"https://ctfe.example.com","hashAlgorithm":"sha-256","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFVzZVVi9MZ1cxM0RIZTcxbmFtdTVTWVBJNm92NQowWXY3QkY2SzRNejE4VHpZYzB5YWFFVjIwWkhLdm5XcnRuUlpDMnJ2UTdSZlNJRnVYdzZCRUNkTUpnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"c885570b8f5368be85c140915749dac7e7c489be345e60ae7ab1d766cc191f69"}],"timestampAuthorities":[{"subject":{"organization":"tsa-organization","commonName":"tsa-common-name"},"uri":"https://tsa.example.com","certChain":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ5ekNDQVhLZ0F3SUJBZ0lVUTVZWXRWRWV2aEd2L2xtVjVHZnRaUkp2ek1zd0NnWUlLb1pJemowRUF3SXcKTURFT01Bd0dBMVVFQ2hNRmJHOWpZV3d4SGpBY0JnTlZCQU1URlZSbGMzUWdWRk5CSUVsdWRHVnliV1ZrYVdGMApaVEFlRncweU16QTJNVEl3T0RVMU1EbGFGdzB6TWpBMk1USXdPRFU0TURsYU1EQXhEakFNQmdOVkJBb1RCV3h2ClkyRnNNUjR3SEFZRFZRUURFeFZVWlhOMElGUlRRU0JVYVcxbGMzUmhiWEJwYm1jd1dUQVRCZ2NxaGtqT1BRSUIKQmdncWhrak9QUU1CQndOQ0FBVDN5VFA4ck9QSzNtM0tGM3dleFhCUlpqcWFGWDVxQXNOblc5ckVpRU50WjRvego5ajMyczVVdUJackptSzYrUzFqTWlzUnpjazJmYVZsQVYxcU1rUEpabzJvd2FEQU9CZ05WSFE4QkFmOEVCQU1DCkI0QXdIUVlEVlIwT0JCWUVGQ1JGUTlvaFRuSWYyeCtCRnBIZzhBRk1wNHZSTUI4R0ExVWRJd1FZTUJhQUZFRmMKYzk2UU9wM0haZkkzUTl6QUlaU3RIa0M4TUJZR0ExVWRKUUVCL3dRTU1Bb0dDQ3NHQVFVRkJ3TUlNQW9HQ0NxRwpTTTQ5QkFNQ0EwY0FNRVFDSUd5OVhkVHJLT0RGMFQyNE9YQTQwNWlIODVEOHBlSDdNV2hyZEl6aDlDMmFBaUJjCmRibEdKTFF3ZS9LMFVWMFFXbSszdjlySHd3ZE8xOEpsNWVGWWFlYnhTZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIwakNDQVhpZ0F3SUJBZ0lVVE9qa2dLU242Z3ZxSTIxRTNETVg2cFhXMHZVd0NnWUlLb1pJemowRUF3SXcKS0RFT01Bd0dBMVVFQ2hNRmJHOWpZV3d4RmpBVUJnTlZCQU1URFZSbGMzUWdWRk5CSUZKdmIzUXdIaGNOTWpNdwpOakV5TURnMU16QTVXaGNOTXpNd05qRXlNRGcxT0RBNVdqQXdNUTR3REFZRFZRUUtFd1ZzYjJOaGJERWVNQndHCkExVUVBeE1WVkdWemRDQlVVMEVnU1c1MFpYSnRaV1JwWVhSbE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUVuSWY0aitycjk2VysxUWl6dlFIU0RsQVBlRlhxcXh6bkhEdUxKMkNVbVJoMjhHTnFLdU45TE1YRApQaHlURDcwOFMrYmxjTUI0Mm42aUF2SmxlMTdtcDZONE1IWXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01CTUdBMVVkCkpRUU1NQW9HQ0NzR0FRVUZCd01JTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkVGY2M5NlEKT3AzSFpmSTNROXpBSVpTdEhrQzhNQjhHQTFVZEl3UVlNQmFBRkd0ckVRL2dCL0xyZU9JUFprUnhpaUVsS0FoMApNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJSDB5TS9HWlRPVlFTM21DZWFBWjR6Z1lxWmcyRDNLaGRvZnVPSWxTCkpQanVBaUVBbEdqWmNHTTNvVThrc2U3aXozeEpqVHYraWRjR3N2NEpZNzRKOTdOdU9VUT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQmxUQ0NBVHFnQXdJQkFnSVVYSWhJS1FET3djV2pwYnY2WVRGajcrWlkvcHN3Q2dZSUtvWkl6ajBFQXdJdwpLREVPTUF3R0ExVUVDaE1GYkc5allXd3hGakFVQmdOVkJBTVREVlJsYzNRZ1ZGTkJJRkp2YjNRd0hoY05Nak13Ck5qRXlNRGcxTXpBNVdoY05Nek13TmpFeU1EZzFPREE1V2pBb01RNHdEQVlEVlFRS0V3VnNiMk5oYkRFV01CUUcKQTFVRUF4TU5WR1Z6ZENCVVUwRWdVbTl2ZERCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkorVgpWQUVGVzgwL25maUpLb01jSE9yZnNnbloyNmRYOWxPUnBheGhGMGRLTDFjL3Y2U3RtUmM3dWtlRk0zekFTWTAvClk5Q1E2UXZtZXFqbnlKeU0rZ1dqUWpCQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQUQKQVFIL01CMEdBMVVkRGdRV0JCUnJheEVQNEFmeTYzamlEMlpFY1lvaEpTZ0lkREFLQmdncWhrak9QUVFEQWdOSgpBREJHQWlFQW1idkZpcndXWjFPa2N0V0tVcFVnYmhaY2szSmlGQjdFcFh3ckY5NTkxcjBDSVFEODB1RGltWEhDCjMwK0hXY0wyejRpaXNCcmhQb2s3T1krNHhIbEh2cGZJdXc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="}]}`

	// validRepository is a valid tar/gzipped repository representing an air-gap
	// TUF repository.
	validRepository = `H4sIAAAAAAAA/+y8WZPjtpI27Gv9io6+1Xcs7IsjzgUpUmtRElXav5hwYKX2XaKkifPf31BV7912e0632z4zlRclEYCIZAJ88kkAWXu33Rxmx83++tOfJgAAwCl9+gQAfPr59B0SQiClHDDyE4AYIfbTK/rnqfReToej2v8EwH6zOf5eu6/Vf/pw/yHyfvxL8Of7M/48P2zW37ePuz0YIb81/gQB9Mn4U4zAT69+iBH/j4//fxdevT7MsrWzr3959d+FV69e/3q8bt3rX169vj/x6//vXnTYOvPr2e0Ps836XgN/Bs8V78vg07W7bGd7d7i3QQDhf0D0D4h6QPxCxS9ITJ5/tHDXw5vOXr0mwmtOrGAICu0wg4YQpAmz0kKvkDDCS+8YRsBjaKlG2EPiKBAeQ+GZeXujp9u+1dxZRCmUT93d1TdTt/pSxcJdZ/bXqTpMf1XLbLOfHaeru2r//1P1q9eHqUKUvWn9dEkhev109V/vb3FWy3davHq9Penl7K7Wa+W890wqwQHRwgmqiUFCSGMsMMAobrFSimktLYCIMA4kNoRooJTXAJHnjv51//uvp95ea4SIthxbzSFSmkuGkLJUakacFNYxTTF22kmlLKMUOc6ZhFxC6DRzHv6NjUUMc1h5aCjEzlAuvJUUaCSkYkpj5IS3SBlrifWYMQgQkEASDxkU2KsvGMtC5pUhVBPusEMYcgQtIZRAjTz0UkqpvBcEOuIcw0oCYTnhUCMBoRbyb2wsTBk3UlILrNOCA2QAo9AqSiXknHKDnUfSWoKMI1Z6LzHlCkOqPMaM4y8YSygluSVSCkkxtgAypogmCnGvnTDUQKKl0JpagCgVWlDArbbYUyCdY39jYzkmJJEIK2SMBIBiyiUQxEKqMVSOAMeAAkQJrjmDHmLuLSZOMgEA5th+aKzCG4O93m+W7j2IPSHlhxaY2Q/1/+aZ+NGjHqd7d5hulnfAhh8M4WGttofp7yvyraP8hxQ5qn3mjoff0eObceyP6TFbucNRrba/o8k3u5+vaPJuwpjN+jA7HN36+OsHA+XV8uAKT02evLA6np7d512/57n1pPJ9Hn/zLHozTWbZ/W4MeIyYFVwoiqUGnBJqCPMAMaOhhYQiSK2SGjNDOTZQY6Kc0JwYp7zWmBLpJfVIII28p8orjYSHyCjDJCSAGCOk9kBSBD0TXHtrMfNYW88ceJrT/yq8+q/Cv/5qBvR/Wz7g/38S+/+3+D9k8IX//wh54f8v/P/vYKwX/v/C/1/4/wv/f+H/L/z/RX6cfMD/387L7x4DfIX/Q0g/5f8MYPbC/3+E/A7/f4dTf0IMsHJH9c59vnEYT/PuPVYv3To7Tl//8gphzt4A7J0jvPe777nA3c1D4QTSmEKBhCcSAICxxRrf0VJjqwx0HGPjsLcQaY608goTriGl0ljvJZTMGW0hs0ILgy0QBkmvHKBMAOWwJUoZJIC0kEipBAIKI82lZ1BR/oYmvFH0A6O88wN/FOe/1Ul/jPPKWmIEVY5gAhmhnCkGOdMUQuC91AwJ57EV3nhAnATSMuYVohjcGRMVGkOiLWUecoWtwo5b5SXF3AgMHQcUGesk1p4YAO5u3VJnCLOQeoyAe8H5v7d8gP9vXsPv38f/fP+fMM5f9v9/hHw+/iVz9O7n7Ul/tz6+4v8BYp/5fwL4i///EfKPu4Rxtd561emHD/Xyq2Y8fiosJJVFHufjWnMzqd/moByk4/qb71GQmijNgnjI+oPSQzaEOKo5DtdqdaKP406dbc60AMZnHlZYkyQ3KHq3sQFXpeIBApNa87we7o/r7qSM9ueUd/1jvXIa5SyMyzZpZP/8Z+FJh7gVfabWX22x/13yhfffn5Zmtvn1DH82++PPW7f61j6+tv4PIPz4/UcAYvzy/v8I+eD9L8fdXr1SLwe9+A0A1OuV/FYuB+yUBXk9DLJ6ffzYtPtKE+/OeR6l48YdEKZn0wrS+CFMg9zP4yQJNtUA9uNCOE2iwaAVJt0kj9NxNEjTepxvo/Hwsp2s5FWvltOkO84rwVNdLc5hbzwkWXfdmOpVa1swqHX+oEEjzgFsRVnWG1auCg1AvdICSUry6Lm+G+d92LrVcSuKJ0loqoW7GuVpkvaqy5MdZVl3JaFedae2ujzreeAqObgmtwAlvXrejvo4uU3VvawVPZcV3hYmNXKJoqAZZq1BGIx7ARz00l7cS8L46VnLYdJMUeWghpOzWdHtuBcPkzB91iC8JK0+qpzq8eQ6HtK5GrXm+vbc4OnH3aTV6qWkHsOpWR2Xthz2bBS3kyB/vkHcTSqtnrm2buml2gtGz1psenF82er1gNTjydkO6WI86m41InmW1WdJAKrlx1218FjXOErjMEj7QUDq5SgP7g2awaZeDtIoGA2yNW89bFCr+AgGtN3viEomF/DaY8VjsQkKaS1JNu4Gsxpx11V5RUezHdLbw0PRLtl5edVu0r48hLvzUvfTdtrhVlUG4wuQo9t2vu+LQnwIo2ojy4r9yb5SvHRrpV1VlIHsnFbXwWmIL23XxLrfDihGm/lgVWqbI+vsOvViCVV8VCqsuuPoOhuzfUR3rYNVXm8PWW3WGt9CRNZ7uJfRtdguF6vRwpiiisLzpbqk536xFiHFJo+FSrNU6pyn9aw5OdhWKS3VIp2PTMdfxbZ9G1XKarQfR30PtyJjHE36Pe3ZKDvZka4PVaNaWK54PriFNZwzlCIWmPy4hevDqAYWJV4qi2g46xu4KDemHXsm2zl/CDvtZDdR0hwXdbAt7H01nkz4Ak/m7UVnNbjNb+Vi89S5OhQ91geN+WXSu7oT7e534WF5HqV5a9nuj+jBXdVm1sCFaDBOGwpOMnKITzW9azebUFRYpzcvBhVcRb51G12u7eBwInUb9C5t3GycH/NuXdNJXz5sCpvNkbdFtser/q65QwPFXDbb4B7rVieoCMaHGKOVies0q9t8VTmCZWvdWD/MB418/FALaWGDu4sxqbIynFwWHWwaZIxFG+re0myG8WDM08Usi3N9i7bdx2a7n8r+ekdaG+HC5NLwtQJgtX4aPBzOu940s4eqZHBVuaB8UzIP5cWus5w2+OGMIlG7OfxwXUZBUupUT1cpR3LZZaLA4tZpcq5Uemk9CtIg3IB+nt6C9v19qKUiDLyIwyC5U5U8zsbRoAt6QVorhUGWh1kcFkp3GOsF9vkHJK5kaX+nxGwGZsFktBUG7xbWjNFmvr6c2vFnEFcI0yDKsnoYBOku7z+2T3JT7JzbKJjGx8PYI6/Qtk4WDbkGt0yETUimm96yr1tDyCrTJi8s+C7E8eN2n2EyDYJ95aLPycPVZr1wjoNefypS4lFPRVc0baXjJIxxsbmKQlBtxuFsPimcduGtNIb927ReWq3PGU1OTbOvHY+0ZRa+d9xfpEi2MBuI6DLO9kFc9jVxla3HiVudp5NuYRAe54ejystkU5msu+38MX5Eh4NerQaNhXqcTS/90fTkyrPz6rBcR70l4xPORdQdTWfXW5AX/JHRcRKIcFgbgWqkl+00Dx/3Q7TYBskuaI7mjdD2ZvU+biJcq/WK6ylY9pPdYd+aVVYiLuzgdWFU6eRrQUyqw7mtsfy49hO7nrR9M6wXhSmqSz2PN2mH1+cuPFyUOqFIDdfhcufbBY+m0XJsGwv/EJIdq9vKoDg8e9s08HIGD6X4EPd2eJINKF0mtai9mI02ybF/uOwcPA/qvtDqH3kwP+35rkiHo964uDw7VZELg/Pz+AA63eZNN1WlXHuYZWkVpjXDiplcDH0Ubcq1Sq3QblSyaS47KIvRMVJb6LNgEreq01raLxelXbNlv1hb8w4AXTjOBgh1kWRjqUh5jK/8WJCPh8PjrR5rdbK8EZcwaFaqt6TcDyf5qRleWzV/lV3Z6IabiuyNVjPNyS3q3FqwXW5NRw+FXbJvmk1Weuht8lVDdRql4aLycN5maPFQeigOO8WThcLJoD7cnnuT7ag667xn1Z85+7+aiLzIXyJf4P97t9jsv+cCwL8R/zP4cv7/h8g3xv+12m20dtFpQtPH4nS36w3daXugnU0Xbgqn0+WyXp+3u86qF1y0mE344CJ6i8phHpeq/Wz+cNzAU7U83jIy6kJM3aU1nvtbErzE/z9KvvD+Hw/q19n66PYrZ2fq6H4F37gQ8LX9P8TIJ/E/AvAl/v8h8pX4PwTzcjkYzd7G//1ee77Imo9rlp13dQRjHCUjth0Nwbmfl7N3ABEHeT0vNN/EsG+i8Iquyvl4mF8q86D/HMImvWjQXRqcZoNKK6xXGmeN07w2Na1knuSF1jy+JlEGk1tAh/fCW5K/LWtHAR3Og/yD+L8Z54ODRq2pjmKXhG+C5+CSDAbVwc2Ww34fxNnjkILJqHGcDLvb8ai7/D2cK7wFunXdk3lxv5dsWITp7HZOa4/RMui4ymi3u9zWtej00EDl/qo7RaLa2jVPLfmQjKJCZ3rtRRyIx6JemiQkaM1mwbmxdJCvtqxFkto4j55Dlc5zqJJGQRZXkzC5280WGmn6tKJSLh+qQdqvhHlSTwLxVBnncVjK00oSJPfYJ6+lTzdqh+E4rsQVYyRLC+0trk18HafyFtQnj8faoiyS8PkG9fweYqigUj3u47SUhaWHvWvXO5NF9zKbxctmMAWF59531ceEyKfoCmRBEvfL9Rq4JqXqpNcepI94VXYqmJBbNt5NMhTh5tRu/KldXz4WGp35KZjFwbI6n5hqgjd9sTg4PrvhS2PeOxdn1lQPZ9IYc9KQvHVq99N/vlDVHyK/gf9Lp/z3Wv79Ov7TT/EfAPzC/36IfA3/r7c7/jff4X9Kx+PjIHbnafVcWq4GtOqPk27jfEsOn+N/8hv4X5sH5i3+Vz7E/3h5stXBVQ8HCzWsgMKk99kSLUyipark4JbM35WRe1kSBZdoHiRv10bD4eVcGKPKIemSvPbsIKL4MuhPRi1Qr3R76WPYV0O4NLg71aNwq1cmH/aCXpiZ3XQxb3fSelgIs+zNRRKGeascBD187XXEvt1p4hVuVnDuLqOwO5nvVGVEd8GhtR7KfTyLW8cJ2dwKco7RgfZP4WTfWDVZ8RHOk9mhezML5NVgGQzgLll0GpMN2uQq+nwpqxCS4GNcL3crqdxMe+u6R5diWNnWMhFUki05dz+D9bhiCncn8GUfMH5q3EifnMgXnMwz7Bfe474Jkjgt16tXObK9fbMdVUAPkfYoIIDOaoJGYutqPBlO97Z+m8oyUsEsNAWrl9XGQ5q7UhP0ByAdror4LPe1PLdtKBpL6ipj5fTl8aONvxfc/wHyG/j/lAv0o/AfEvzZ/h94yf/5IfI1/F/2yuWgt3uH/6P6tN5Mo3ZuhvOtPrNxrzLnxcm4tP0C/v8I/r/5Df7/fvctuCStD/l/fyXPNgond4YdXp9p7Z1xv6W4QR7XAlAPwkZxUBgEcWUoQGntZ43mJjG19t4fsvUEMTuSy3Z3qy7TCrDNB2hKZ/Z4XHUNPy1cJcG34HEMSoWxLKcsPa/cbr6+Nq5JMRvO03kYJAF5Qt/omcLfDRaG86DzhP/d5Bn/e8E9AqmVkhA8N87SYRh29+oSd0jgrwzPZxGaxGa8mTYes7p92qF867HugUSrUQiisHpn3yt9rsz2+XAC2wtzHDb7236mpxOzwI1ZJeTxdpTvK5JKuAflehoJcIpmq1GtXMCgWBuaB3Qjs9kh3E87mwVvj4vkUlvWzltfP+UvsP2fKp/j//dPAf3a+Q8KPz3/Rxl9wf8fIr9z/vttHs+fcPz7kxSh12+PHH7h9Dfk4uuHvzWGhgtqGXREKM+9p8hyioxlQCGFPPJSGm0JVtooSDRxilAPuVVAeyE1pMQaKpnlzkNplMWYWAuNJAQIzrXERimJBPLOEES94ARKb43mQHqlPz78bU6H42b1oaKz7HDc7N37olevTweVPZm53KvEb3PbXr0+HNXx9GS9wBxnZ/e+5rSf3Yufu3rOR/sohe+zY1tfOkoPKP+6NZmVXHHtADbceMyMIM5jqhwgUmPqqZEcQsuMR9I7qgxWFBnPmdBOGgK9vrfWnBMBETHCQGMUZlBjoIgUXgAABSKCcUC8EgRrAI1g2CAvnNT4W6xZebLC97Dnu22wf3dSGqykwZAASDWFRDh+nzlaSmMsIxgBipxDggsALHbsDnqeSsYBY0hpRyxRRCqPsAbKGAwp44hpaAlH3iDKNaDeS44tBEp6T6nE1nIIDSEKEfZNk7J7f/jvYcXf3kz4glmZRF83K/JEOgC8Y1Jpyj02zErnsHdSeu+QwowoYg3EnFotgGbOe6SQUQQix6z1kEDIPLCUC+g4UJpA5gDGQmrpOFLQUYg1tIZxeh8zozwGCkmmEVLfNDt7j8H3MuqHK3RfMqUgf8CUTjOMMPOSKKaEgtJR5ICgVFDvkUTKGasw5pgiTIikjkFrEQBSWgOpgMwiKhXhnHGpAKfeYCSIQcQT4xx3ElNvBaBIcckwgxQCQ6STSDpspfmbmPLDYPdLpoTw66aESHCllEbIC04hwchYyqj0mgt7xzXMCXQUKS0EUh4hrwx0TFvqGBcOI+848FZ5AwTTzFpjicMAe0etR1BZSjkjCklCqQTIEEc5lMgBpTU38K815f8gu+mbU38/ym4CwiHrsHOeEWwpU8xYpYDHlmvOBZGKYIWFw5JR6yik4u6mGGX3NkwJrIGD2GKIOXfMUiCJ1cIJbh1lEmnnibcMeWAoRBIjY4xggkAgBTIasP/87KYP+f/bfOnvHQF8df2H4k/PfyDwsv/7Q+T3+P+7/Pk/OwH0o8zjLyLwH6BbwlGNlEEMUM+k1kRqxrAn1lJuPPSKM6g9JYhgjxj1nlpumbWEKgMc4JRr74EiDlACrXeMECy9Fw4Zrg0HzkJkNRRQQS+EFtI6iJEQxEMIhf5+CaDf/D8JPoJIYsgdHQ11nCvgkdGcAokYJFQChrhR3CoLpaYeAuo5kQRx4hQFTlIKkSIWC2CYoVhwYT3UHDqCPPSUKAy9VZgbZQjzXgl0j6DAnb1aw6hUGtj/fIh8kRd5kRf5Xyn/LwAA///eye2RAF4AAA==`

	// rootJSON is a valid base64 encoded root.json for above TUF repository.
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDIzLTEyLTEyVDA4OjU4OjI4WiIsCiAgImtleXMiOiB7CiAgICI0OGZiNzRkODYyMThiZTM2MWM0NDJiNDZkOWQxZmEyOGM4ZjlmZTYzMjBmMzFkNWIyM2YxNGU1MDhmMzE4ZjZjIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJhZWZmZjY5YTg3MDRiOGU4NWI0YzI4ODljY2QwYzBjYTdkM2FhYTZiYjlkMDEyNDY3MDkzYzQ0YjBhYWZiMDI0IgogICAgfQogICB9LAogICAiYjIyNGJkNzNkYjcxMmFiNzk2MjJhZDU5YjY0ZTk4ZGU2YjUzM2ViZTlhYWQ2NTUyZTc3NjkxNzkxMWViNmVmMSI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiNGM2ZTNhZjFjNTEzZWM1NzhmZDk1MGIyODlhNmFiMzJlOGZkMmFjZGQ0ZGYzNjYxMDIwOTA5NGYxNjE4M2ZhNCIKICAgIH0KICAgfSwKICAgImQxNmZhYzQ1YjQ3ZTNlMjMxNzIxZDQ0NTQxYjJmMWY5OTk5YWZmODQxZTRlZTYzYTkwOGQ3NDcxYjI4MTFiODkiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjM1NjdjOTk1ZDBkZWI4NzAyYzA2NTFkYTU1OTE3NzU3YzNlZjI5ZGQ0MmNlNGQ5ZmY5MzU3YTMxNWFmMzM2NzMiCiAgICB9CiAgIH0sCiAgICJkOGFhOTdkNDk5ODk1MzNkMDE2NmE0YjRhMjdmYmU4YzVjMTRiOThiYjVkMDI1NThiODUwN2RiZDNmNTA5ZWU2IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJlNjg5NDkyM2EyY2M5MDA1MzU3OTA4NGQxNWIzMWFlNDBlNjBhMDRhODdiNzYxZjEzN2ZkMzRlOTY4MDAzNzNkIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiZDE2ZmFjNDViNDdlM2UyMzE3MjFkNDQ1NDFiMmYxZjk5OTlhZmY4NDFlNGVlNjNhOTA4ZDc0NzFiMjgxMWI4OSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJkOGFhOTdkNDk5ODk1MzNkMDE2NmE0YjRhMjdmYmU4YzVjMTRiOThiYjVkMDI1NThiODUwN2RiZDNmNTA5ZWU2IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiYjIyNGJkNzNkYjcxMmFiNzk2MjJhZDU5YjY0ZTk4ZGU2YjUzM2ViZTlhYWQ2NTUyZTc3NjkxNzkxMWViNmVmMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiNDhmYjc0ZDg2MjE4YmUzNjFjNDQyYjQ2ZDlkMWZhMjhjOGY5ZmU2MzIwZjMxZDViMjNmMTRlNTA4ZjMxOGY2YyIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiZDE2ZmFjNDViNDdlM2UyMzE3MjFkNDQ1NDFiMmYxZjk5OTlhZmY4NDFlNGVlNjNhOTA4ZDc0NzFiMjgxMWI4OSIsCiAgICJzaWciOiAiNjBmMzI2ZDg3OGE1MzliMDc1NDVjNDZmMDI2Y2IxZDE0NTIxNWRhOWIzNmM1NzNjMWIzNGFlOGI3NGNlYWZiYjM1NDlmOTVmMjgyYjJmZjVhZmFiMjhmMTJjYWM2OTE0MDRjYzg5YmYwOTUyMWY2ODdiZmRkMzZmM2JkZjZlMDkiCiAgfQogXQp9`

	// These are the public keys from an airgapped TUF repository.
	/* TODO(vaikas): Uncomment and test these make the roundtrip
		tufCTFE = `-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJvCJi707fv5tMJ1U2TVMZ+uO4dKG
		aEcvjlCkgBCKXbrkumZV0m0dSlK1V1gxEiyQ8y6hk1MxJNe2AZrZUt7a4w==
		-----END PUBLIC KEY-----
	`
		tufFulcio = `-----BEGIN CERTIFICATE-----
		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
		-----END CERTIFICATE-----
	`
		tufRekor = `-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEenlW+tMJ9ymhl858kKiD14CC06x9
		r36rTqTSiLYrdl2ZVE3mOD/KcbyBZM1/RHVKx/g1r3d0YSoVCKbF4DAvcQ==
		-----END PUBLIC KEY-----
	`
	*/

	// this is the marshalled entry for when we construct from the repository.
	marshalledEntryFromMirrorFS = `{"certificateAuthorities":[{"subject":{"organization":"","commonName":""},"uri":"","certChain":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZ3ekNDQTZ1Z0F3SUJBZ0lJWVNLZHJGSzNxdnd3RFFZSktvWklodmNOQVFFTEJRQXdmakVNTUFvR0ExVUUKQmhNRFZWTkJNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVFlXNGdSbkpoYm1OcApjMk52TVJZd0ZBWURWUVFKRXcwMU5EZ2dUV0Z5YTJWMElGTjBNUTR3REFZRFZRUVJFd1UxTnpJM05ERVpNQmNHCkExVUVDaE1RVEdsdWRYZ2dSbTkxYm1SaGRHbHZiakFlRncweU16QTJNVEl3T0RVM016aGFGdzB5TkRBMk1USXcKT0RVM016aGFNSDR4RERBS0JnTlZCQVlUQTFWVFFURVRNQkVHQTFVRUNCTUtRMkZzYVdadmNtNXBZVEVXTUJRRwpBMVVFQnhNTlUyRnVJRVp5WVc1amFYTmpiekVXTUJRR0ExVUVDUk1OTlRRNElFMWhjbXRsZENCVGRERU9NQXdHCkExVUVFUk1GTlRjeU56UXhHVEFYQmdOVkJBb1RFRXhwYm5WNElFWnZkVzVrWVhScGIyNHdnZ0lpTUEwR0NTcUcKU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRREFYVmduN05MbzJOK1MwVjVPVVA4Rmc5azF5VDYrdCtLMApRSE1Nb2V6MWdINGV5bUNtNVhpcTJicHNMK2RsNnZseWJlWk94TEJxdmxiVVFPUVA3ZGFGVll4MDlYenBqclU4CkVzQkRHSmdnK1VackYreFJIL3FHOEMwOVB1bXlWdVczeE9lSzNiVU9BNTMyb2pWbS9PY3Q2UHFQSSsvMkZmRC8KbVJZRHlpWTZyRDVxTnNkYWZicHNnSGlOWXpCMjRucjFyOUR5K09DK0dEa2NjK2FEQnZ4R2w1dlUrSEQyYTZaUwpGSy8vUHZoSWdLWnNkTi9RL0hEYndYY1BmeThwT3pYRkNhWHJZRFVmMXA4ZzY3MlpVVGJmNlhndWRYYklXYUpHCmxtN3dWekJIM3c2MlEyNkFjd3RwMW5zWEgway83L0M4RFdpVWMxa0NKaFBkdjRwajdMQlBPTXFaYTljdGtJMHAKcmZHRVpaN2szWmpPa1BtVnpqekMrS3VQeWUyRFNJVkpqeFpUeWV1NVJycUJzbHZYUXdObE9VWDVzZXlhb2lKMwpEVllRSmExWmc0c0V1SGJxT0tLMThGNlBUaitBRjNHMmZOelh4eU9Bc3U0SWRBVHhPM0tKdlN3UkliNVpVOUxvCm9vdDdPOGdyM21VcUtxMlZhNmVnaW8zVDZSR1oyKzBZc0UzMm1jRUk1Z0lkd21GdDBsTm5KbkxqVkp3WUxIQjUKbzNSa1k0RzZDMVp4a1AzY0o0WTM4TzFiVGxjb1dFVlk3UWtpZ0V3YnpEcFJTS09VUTlVbnE0Tm84ZUJNeEpmSAowNkhVUUFMc3ZxVGhnZHNHOTYxbUZ4MndvL2NMQ2txUGxoSjdzdjJEOEh6ZTNMeWxEQU0vUEd1eTk5WDlsUjY4CjZFTnVadkZGVFFJREFRQUJvMFV3UXpBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFUQWRCZ05WSFE0RUZnUVVxYThpaTBpQVpYcDhjM3FrZGNZMm9qbnh1T0V3RFFZSktvWklodmNOQVFFTApCUUFEZ2dJQkFBUXF3VVNPdTlvK1B2TzJBaEV0c1lmMmZhMnBJNGtKOW4wemc4QksxNGhvVGxVYk5XMTZGaEs3Cms3cUIzRVNwcmczNGhBQXJGeGJ2TUx5ZGdUQmozQVRVaDhRNGYyVGFEeTJoTlFZTUJFMytLbURCMEdLRUJpaloKdXFCei9ZMVV6aEkvbW52ZzVNdUtjckh0dDVOY2tmVHRyeDk4TXAxZ1Y4RHhZZ3JBRUNmSDh5OU5TWmVtdmhaUgpWQnRqc3Rhd0M0b0ZablJPd1NFUzJzc2JtbVZKa2FTaWh4VVhodWVDaXZtc2xuRFRsNjdaNzc4RFJYaGl5ekF3CmZ0NjVZTUE4QldIWDBHRGJsT1F3QlNyVzJrcEFNcUFLWGpKQmRUaUlVM0syM0hIVCtuaDBsVU1xc3JOaUZtOEUKcTF5a2NhL3VmSEFFNEdXamRINnd0bmZaZG5aT2ZLQkkrOGMrYXhJd0VvUVA3SWplQnN4YWF1MkRhV25CbHFmTwpmMmhEbFlkSmtmTEI0cTZJZEZWK1d2ZmRLYzF4djBML0VzRVRxM1pnVjU1bE1IRE9raVhvTXRVc3hxZTF2VklmCk5VdDdBanVyN3ErNVdYVFkrbHZlYUY5a2Mzd3ZZczBQUkt6YkthRkNITGlnUUcxUUhjNitnOWtXZkREb0NIRkgKT0pGZ2h3OVAyZ0UydERhcDFmZ0FaRU5HaEhRVUMrOWRuNmxVK0huN1AwMFIxWWdWMjJSMjk2WTlhNENZM3k3dAo5U3NzU3pJRWJhdWQ3SkUvMzBLRkd6TUNVQlp3dUtCeU5IZnk5UjlKUkJvRjlUWG1pYjc0ekRQek4xT0NOaFhMCnFNcktjb2cvTFRvd21KYVBKL1drRkx2cGcya0wvTCtXUCt1ZDE4ZTlBSVdwdlRacFhHaVAKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}],"tLogs":[{"baseURL":"","hashAlgorithm":"","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSEh6WG5lRHVaNVFTK2hxcVRXZXVwczVQb1Ixbwp1dXh4bm52cHFQbVRBeGI4aVo3Vng4VGtGc2pFL0dVZ2pMdG8xdUdDWXA2NFhSMTM1ZXhOWWpmek1BPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"7b12eee368e5f2853aebd039b8aee610b7aa165c801be86497fafb159babef05"}],"ctLogs":[{"baseURL":"","hashAlgorithm":"","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFVzZVVi9MZ1cxM0RIZTcxbmFtdTVTWVBJNm92NQowWXY3QkY2SzRNejE4VHpZYzB5YWFFVjIwWkhLdm5XcnRuUlpDMnJ2UTdSZlNJRnVYdzZCRUNkTUpnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"c885570b8f5368be85c140915749dac7e7c489be345e60ae7ab1d766cc191f69"}],"timestampAuthorities":null}`

	// Just some formatting strings that make it easier to construct patches
	// to config map.
	replacePatchFmtString = `[{"op":"replace","path":"/data/%s","value":"%s"}]`
	removePatchFmtString  = `[{"op":"remove","path":"/data/%s"}]`
)

// testmap with prepopulated (grabbed from an instance of scaffolding) entries
// for creating TrustRoot resource.
// ctfe   => CTLog Public Key
// fulcio => CertificateAuthority certificate
// rekor  => TLog PublicKey
// tsa    => TimeStampAuthorities certificate chain (root, intermediate, leaf)
var sigstoreKeys = map[string]string{
	"ctfe":   ctfePublicKey,
	"fulcio": fulcioCert,
	"rekor":  rekorPublicKey,
	"tsa":    tsaCertChain,
}

func TestReconcile(t *testing.T) {
	rootJSONDecoded, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("Failed to decode rootJSON for testing: %v", err)
	}
	validRepositoryDecoded, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("Failed to decode validRepository for testing: %v", err)
	}

	table := TableTest{{
		Name: "bad workqueue key",
		// Make sure Reconcile handles bad keys.
		Key: "too/many/parts",
	}, {
		Name: "key not found",
		// Make sure Reconcile handles good keys that don't exist.
		Key: "foo/not-found",
	}, {
		Name: "TrustRoot not found",
		Key:  testKey,
	}, {
		Name: "TrustRoot is being deleted, doesn't exist, no changes",
		Key:  testKey,
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootDeletionTimestamp),
		},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm created and finalizer",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
			)},
		WantCreates: []runtime.Object{
			makeConfigMapWithSigstoreKeys(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchFinalizers(system.Namespace(), trName),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot" finalizers`),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with entry, no changes",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
			),
			makeConfigMapWithSigstoreKeys(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchFinalizers(system.Namespace(), trName),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot" finalizers`),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with different, replace patched",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replacePatchFmtString, trName, marshalledEntry),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with different, replace patched but fails",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replacePatchFmtString, trName, marshalledEntry),
		},
		WithReactors: []clientgotesting.ReactionFunc{
			InduceFailure("patch", "configmaps"),
		},
		WantErr: true,
		WantEvents: []string{
			Eventf(corev1.EventTypeWarning, "InternalError", "inducing failure for patch configmaps"),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				WithInitConditionsTrustRoot,
				WithObservedGenerationTrustRoot(1),
				WithMarkInlineKeysOkTrustRoot,
				WithMarkCMUpdateFailedTrustRoot("inducing failure for patch configmaps"),
			)}},
	}, {
		Name: "Two SigstoreKeys, one deleted, verify it is removed",
		Key:  testKey2,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			NewTrustRoot(tkName2,
				WithTrustRootUID(uid2),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				WithTrustRootDeletionTimestamp,
			),
			makeConfigMapWithTwoEntries(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchRemoveFinalizers(system.Namespace(), testKey2),
			makeRemovePatch(tkName2),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot-2" finalizers`),
		},
	}, {
		Name: "With repository",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithRepository("targets", rootJSONDecoded, validRepositoryDecoded),
				WithTrustRootFinalizer,
			),
		},
		WantCreates: []runtime.Object{
			makeConfigMapWithMirrorFS(),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithRepository("targets", rootJSONDecoded, validRepositoryDecoded),
				WithTrustRootFinalizer,
				MarkReadyTrustRoot,
			)}},
	}}

	logger := logtesting.TestLogger(t)
	table.Test(t, MakeFactory(func(ctx context.Context, listers *Listers, cmw configmap.Watcher) controller.Reconciler {
		r := &Reconciler{
			configmaplister: listers.GetConfigMapLister(),
			kubeclient:      fakekubeclient.Get(ctx),
		}
		return trustroot.NewReconciler(ctx, logger,
			fakecosignclient.Get(ctx), listers.GetTrustRootLister(),
			controller.GetEventRecorder(ctx),
			r)
	},
		false,
		logger,
		nil, // Only meaningful for CIP reconciler, but reuse the same factory.
	))
}

func makeConfigMapWithSigstoreKeys() *corev1.ConfigMap {
	ret := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: make(map[string]string),
	}
	source := NewTrustRoot(trName, WithSigstoreKeys(sigstoreKeys))
	c := &config.SigstoreKeys{}
	c.ConvertFrom(context.Background(), source.Spec.SigstoreKeys)
	for i := range c.TLogs {
		c.TLogs[i].LogID = rekorLogID
	}
	for i := range c.CTLogs {
		c.CTLogs[i].LogID = ctfeLogID
	}
	marshalled, err := resources.Marshal(c)
	if err != nil {
		panic("failed to marshal test SigstoreKeys")
	}
	ret.Data[trName] = marshalled
	return ret
}

func makeConfigMapWithMirrorFS() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{"test-trustroot": marshalledEntryFromMirrorFS},
	}
}

// Same as above, just forcing an update because the entry in the configMap
// is not what we expect, it doesn't really matter what it is.
func makeDifferentConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{
			trName: `{"uid":"test-uid","resourceVersion":"0123456789",
images":[{"glob":"ghcr.io/example/*"}],"authorities":[{"name":"authority-0","key":{"data":"-----BEGIN NOTPUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END NOTPUBLIC KEY-----"}}]}`,
		},
	}
}

// Same as MakeConfigMap but a placeholder for second entry so we can remove it.
func makeConfigMapWithTwoEntries() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{
			trName:  marshalledEntry,
			tkName2: "remove me please",
		},
	}
}

// makePatch makes a patch that one would be able to patch ConfigMap with.
// fmtstr defines the ops/targets, key is the actual key the operation is
// in the configmap. patch is the unescape quoted (for ease of readability in
// constants) that will then be escaped before creating the patch.
func makePatch(fmtstr, key, patch string) clientgotesting.PatchActionImpl {
	escapedPatch := strings.ReplaceAll(patch, "\"", "\\\"")
	out := fmt.Sprintf(fmtstr, key, escapedPatch)
	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.SigstoreKeysConfigName,
		Patch: []byte(out),
	}
}

// makeRemovePatch makes a patch suitable for removing from a configmap.
func makeRemovePatch(key string) clientgotesting.PatchActionImpl {
	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.SigstoreKeysConfigName,
		Patch: []byte(fmt.Sprintf(removePatchFmtString, key)),
	}
}

func patchFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":["` + FinalizerName + `"],"resourceVersion":"` + resourceVersion + `"}}`
	action.Patch = []byte(patch)
	return action
}

func patchRemoveFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":[],"resourceVersion":"` + resourceVersion + `"}}`
	action.Patch = []byte(patch)
	return action
}

// TestConvertFrom tests marshalling / unmarshalling to the configmap and back.
// This is here instead of in the pkg/apis/config because of import cycles and
// having both types v1alpha1.SigstoreTypes and config.SigstoreTypes being
// available makes testing way easier, and due to import cycles we can't put
// that in config and yet import v1alpha1.
func TestConvertFrom(t *testing.T) {
	source := v1alpha1.SigstoreKeys{}

	itemsPerEntry := 2

	// Create TransparencyLogInstances.
	// Values are not valid for proper usage, but we want to make sure
	// we properly handle the serialize/unserialize so we use fixed values
	// for testing that.
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"tlog", "ctlog"} {
			entry := v1alpha1.TransparencyLogInstance{
				BaseURL:       *apis.HTTP(fmt.Sprintf("%s-%d.example.com", prefix, i)),
				HashAlgorithm: fmt.Sprintf("%s-hash-%d", prefix, i),
				PublicKey:     []byte(fmt.Sprintf("%s-publickey-%d", prefix, i)),
			}
			switch prefix {
			case "tlog":
				source.TLogs = append(source.TLogs, entry)
			case "ctlog":
				source.CTLogs = append(source.CTLogs, entry)
			default:
				panic("invalid type")
			}
		}
	}
	// Create CertificateAuthorities.
	// Values are not valid for proper usage, but we want to make sure
	// we properly handle the serialize/unserialize so we use fixed values
	// for testing that.
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"fulcio", "tsa"} {
			entry := v1alpha1.CertificateAuthority{
				Subject: v1alpha1.DistinguishedName{
					Organization: fmt.Sprintf("%s-organization-%d", prefix, i),
					CommonName:   fmt.Sprintf("%s-commonname-%d", prefix, i),
				},
				URI:       *apis.HTTP(fmt.Sprintf("%s-%d.example.com", prefix, i)),
				CertChain: []byte(fmt.Sprintf("%s-certchain-%d", prefix, i)),
			}
			switch prefix {
			case "fulcio":
				source.CertificateAuthorities = append(source.CertificateAuthorities, entry)
			case "tsa":
				source.TimeStampAuthorities = append(source.TimeStampAuthorities, entry)
			default:
				panic("invalid type")
			}
		}
	}
	converted := &config.SigstoreKeys{}
	// convert from v1alpha1 to config and let's marshal to configmap and back
	// to make sure we exercise the path from:
	// v1alpha1 => config => configMap => back (this is what reconciler will
	// use to call cosign verification functions with).
	converted.ConvertFrom(context.Background(), &source)
	marshalled, err := resources.Marshal(converted)
	if err != nil {
		t.Fatalf("Failed to marshal entry: %v", err)
	}
	tkMap := map[string]string{"test-entry": marshalled}
	skMap, err := config.NewSigstoreKeysFromMap(tkMap)
	if err != nil {
		t.Fatalf("Failed to construct from map entry: %v", err)
	}
	sk := skMap.SigstoreKeys["test-entry"]
	if len(sk.TLogs) != 2 {
		t.Errorf("Not enough TLog entries, want 2 got %d", len(sk.TLogs))
	}
	if len(sk.CTLogs) != 2 {
		t.Errorf("Not enough CTLog entries, want 2 got %d", len(sk.CTLogs))
	}
	if len(sk.CertificateAuthorities) != 2 {
		t.Errorf("Not enough CertificateAuthority entries, want 2 got %d", len(sk.CertificateAuthorities))
	}
	if len(sk.TimeStampAuthorities) != 2 {
		t.Errorf("Not enough TimestampAuthorities entries, want 2 got %d", len(sk.TimeStampAuthorities))
	}
	// Verify TLog, CTLog
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"tlog", "ctlog"} {
			var entry config.TransparencyLogInstance
			switch prefix {
			case "tlog":
				entry = sk.TLogs[i]
			case "ctlog":
				entry = sk.CTLogs[i]
			default:
				panic("invalid type")
			}
			wantURL := fmt.Sprintf("http://%s-%d.example.com", prefix, i)
			wantHash := fmt.Sprintf("%s-hash-%d", prefix, i)
			wantPublicKey := fmt.Sprintf("%s-publickey-%d", prefix, i)
			if entry.BaseURL.String() != wantURL {
				t.Errorf("Unexpected BaseURL for %s %d wanted %s got %s", prefix, i, wantURL, entry.BaseURL.String())
			}
			if entry.HashAlgorithm != wantHash {
				t.Errorf("Unexpected HashAlgorithm for %s %d wanted %s got %s", prefix, i, wantHash, entry.HashAlgorithm)
			}
			if string(entry.PublicKey) != wantPublicKey {
				t.Errorf("Unexpected PublicKey for %s %d wanted %s got %s", prefix, i, wantPublicKey, string(entry.PublicKey))
			}
		}
	}
	// Verify CertificateAuthority, TimeStampAuthorities
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"fulcio", "tsa"} {
			var entry config.CertificateAuthority
			switch prefix {
			case "fulcio":
				entry = sk.CertificateAuthorities[i]
			case "tsa":
				entry = sk.TimeStampAuthorities[i]
			default:
				panic("invalid type")
			}
			wantOrganization := fmt.Sprintf("%s-organization-%d", prefix, i)
			wantCommonName := fmt.Sprintf("%s-commonname-%d", prefix, i)
			wantURI := fmt.Sprintf("http://%s-%d.example.com", prefix, i)
			wantCertChain := fmt.Sprintf("%s-certchain-%d", prefix, i)

			if entry.Subject.Organization != wantOrganization {
				t.Errorf("Unexpected Organization for %s %d wanted %s got %s", prefix, i, wantOrganization, entry.Subject.Organization)
			}
			if entry.Subject.CommonName != wantCommonName {
				t.Errorf("Unexpected CommonName for %s %d wanted %s got %s", prefix, i, wantCommonName, entry.Subject.CommonName)
			}
			if string(entry.CertChain) != wantCertChain {
				t.Errorf("Unexpected CertChain for %s %d wanted %s got %s", prefix, i, wantCertChain, string(entry.CertChain))
			}
			if entry.URI.String() != wantURI {
				t.Errorf("Unexpected URI for %s %d wanted %s got %s", prefix, i, wantURI, entry.URI.String())
			}
		}
	}
}
