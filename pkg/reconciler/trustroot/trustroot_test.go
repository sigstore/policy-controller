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
	ctfePublicKey   = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJvCJi707fv5tMJ1U2TVMZ+uO4dKG
aEcvjlCkgBCKXbrkumZV0m0dSlK1V1gxEiyQ8y6hk1MxJNe2AZrZUt7a4w==
-----END PUBLIC KEY-----
`
	fulcioCert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`
	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7D2WvgqSzs9jpdJsOJ5Nl6xg8JXm
Nmo7M3bN7+dQddw9Ibc2R3SV8tzBZw0rST8FKcn4apJepcKM4qUpYUeNfw==
-----END PUBLIC KEY-----
`
	tsaCertChain = `-----BEGIN CERTIFICATE-----
MIIBzDCCAXKgAwIBAgIUfyGKDoFa7y6s/W1p1CiTmBRs1eAwCgYIKoZIzj0EAwIw
MDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0
ZTAeFw0yMjExMDkyMDMxMzRaFw0zMTExMDkyMDM0MzRaMDAxDjAMBgNVBAoTBWxv
Y2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAR3KcDy9jwARX0rDvyr+MGGkG3n1OA0MU5+ZiDmgusFyk6U
6bovKWVMfD8J8NTcJZE0RaYJr8/dE9kgcIIXlhMwo2owaDAOBgNVHQ8BAf8EBAMC
B4AwHQYDVR0OBBYEFHNn5R3b3MtUdSNrFO49Q6XDVSnkMB8GA1UdIwQYMBaAFNLS
6gno7Om++Qt5zIa+H9o0HiT2MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqG
SM49BAMCA0gAMEUCIQCF0olohnvdUq6T7/wPk19Z5aQP/yxRTjCWYuhn/TCyHgIg
azV3air4GRZbN9bdYtcQ7JUAKq89GOhtFfl6kcoVUvU=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB0jCCAXigAwIBAgIUXpBmYJFFaGW3cC8p6b/DHr1i8IowCgYIKoZIzj0EAwIw
KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjIx
MTA5MjAyOTM0WhcNMzIxMTA5MjAzNDM0WjAwMQ4wDAYDVQQKEwVsb2NhbDEeMBwG
A1UEAxMVVGVzdCBUU0EgSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEKDPDRIwDS1ZCymub6yanCG5ma0qDjLpNonDvooSkRHEgU0TNibeJn6M+
5W608hCw8nwuucMbXQ41kNeuBeevyqN4MHYwDgYDVR0PAQH/BAQDAgEGMBMGA1Ud
JQQMMAoGCCsGAQUFBwMIMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNLS6gno
7Om++Qt5zIa+H9o0HiT2MB8GA1UdIwQYMBaAFB1nvXpNK7AuQlbJ+ya6nPSqWi+T
MAoGCCqGSM49BAMCA0gAMEUCIGiwqCI29w7C4V8TltCsi728s5DtklCPySDASUSu
a5y5AiEA40Ifdlwf7Uj8q8NSD6Z4g/0js0tGNdLSUJ1do/WoN0s=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBlDCCATqgAwIBAgIUYZx9sS14En7SuHDOJJP4IPopMjUwCgYIKoZIzj0EAwIw
KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjIx
MTA5MjAyOTM0WhcNMzIxMTA5MjAzNDM0WjAoMQ4wDAYDVQQKEwVsb2NhbDEWMBQG
A1UEAxMNVGVzdCBUU0EgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAbB
B0SU8G75hVIUphChA4nfOwNWP347TjScIdsEPrKVn+/Y1HmmLHJDjSfn+xhEFoEk
7jqgrqon48i4xbo7xAujQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBQdZ716TSuwLkJWyfsmupz0qlovkzAKBggqhkjOPQQDAgNI
ADBFAiBe5P56foqmFcZAVpEeAOFZrAlEiq05CCpMNYh5EjLvmAIhAKNF6xIV5uFd
pSTJsAwzjW78CKQm7qol0uPmPPu6mNaw
-----END CERTIFICATE-----
`

	// This is the marshalled entry from above keys/certs with fixed values
	// (for ease of testing) for other parts.
	marshalledEntry = `{"certificateAuthorities":[{"subject":{"organization":"fulcio-organization","commonName":"fulcio-common-name"},"uri":"https://fulcio.example.com","certChain":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZ3ekNDQTZ1Z0F3SUJBZ0lJSzd4YitycVk0Z0V3RFFZSktvWklodmNOQVFFTEJRQXdmakVNTUFvR0ExVUUKQmhNRFZWTkJNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVFlXNGdSbkpoYm1OcApjMk52TVJZd0ZBWURWUVFKRXcwMU5EZ2dUV0Z5YTJWMElGTjBNUTR3REFZRFZRUVJFd1UxTnpJM05ERVpNQmNHCkExVUVDaE1RVEdsdWRYZ2dSbTkxYm1SaGRHbHZiakFlRncweU1qRXlNRGd3TWpFM05URmFGdzB5TXpFeU1EZ3cKTWpFM05URmFNSDR4RERBS0JnTlZCQVlUQTFWVFFURVRNQkVHQTFVRUNCTUtRMkZzYVdadmNtNXBZVEVXTUJRRwpBMVVFQnhNTlUyRnVJRVp5WVc1amFYTmpiekVXTUJRR0ExVUVDUk1OTlRRNElFMWhjbXRsZENCVGRERU9NQXdHCkExVUVFUk1GTlRjeU56UXhHVEFYQmdOVkJBb1RFRXhwYm5WNElFWnZkVzVrWVhScGIyNHdnZ0lpTUEwR0NTcUcKU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRQzE0MkVqbGcyUXhJd3BOamJhZVcvZnQ5c0gxVFhVNkNXZwpic3ZWcDc3dlJnY2tTbnBNM1JUQy9nd0V3Skh0WCtHT1RyUDlybzZuRkpOM0czaGNGbmFNSExLZEdyb2Y5aUh1Ci93L2xaTHdRelh6VlQrMFp5Wnh5dEhBV0dGQnZtWU00SjMzakg2RGo5UHZxT053dFNCU21aQlBjL0gvOEV2WXMKVXp4UFd1a2hPdG90U0gzVlhEcVo0amw5Nk1MZTArNWcyV2k3TXhSWDQ0WDFSaVBTMTRiYTFFUzUzOGJUaGhjUQo0U01qM3VoYmRzQ0lrY203ZUY0RVkzcEVYUXBYRUVHblpHZndZZ1FyKzZjVDA3WmQvV0RNME5YM0t4SDZxUms5CmdEalBuZmNNdUZiT1RiZkQvbnV2eDZGTlg2T1VyenJaU2dsa0x2Y1BJQlZPVzdMbjQxTEFiN2FYbWJXTEZFSm4KdUxvb1BwWVlyKzZOaG5GRE5HcHNCS0dLci9rdmJReURLS3N0M0NLajlvdFBTMTM2M25pNDFxbm9BN1lXU3F4dwp6NDE4NWRLS2MrWTd5dkpRc1JscjZxRzFzTkxPK2M3N2ZTUzVWWkltek5vekJjUmt1TEpGbFgrV0IwdXpnUVU1CnM0NUlaVytmSzkybmZ1OE1tS2p6SFIraWR5cjRPeWpTMFlTTjNHTWdjMFVQN0s2aFZwaExlZEFwRnB5a0JTRkcKVWdpUFp3clQrbUdTVmdtT1hxNW4xZFFUQ0QxNGxFaDJxdDMvcmZmOHpOYzBDTUFOV3liYU1HQkdRNGJoVlZYZQpSS1l4OXUyUFpqUHY1M3A3WWIvRENkcW5HRUR3L0hDQkRpQ3M0b1llNGRhRTM2eFVvanhEU20zRGFlTkc2OHo5ClJMN2dmVWpBeFFJREFRQUJvMFV3UXpBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFUQWRCZ05WSFE0RUZnUVVmK2xiTlgwV2g0aCtRMFNSdGhSSytLZkxqcUV3RFFZSktvWklodmNOQVFFTApCUUFEZ2dJQkFFaEpqYTBaU0t3WGNhT1hDWVJYVEUwNitKYnBlekk1TGV2QmhtYlJRSzc4OVJxMTBKZUFYYTdtCkVUb1JHbEdGTEgydURUMTFtc0ZLeU0zdjY3S2xFMVNZVmNxS21DbFlmSVZFWUgzTGEwdUkrOXJIWm5XZ2I0QmwKeTFCOHdibEtKemhZUUQ5WjRIL2dzK0JBc29SWDVWb0Z5SWdrTkJrMXAzZnRhVkNia1F2UzBPWXRZczVpdzRlSwpjSTcxL0lzVElUM1pwcGo5UjhJR3Nxd0xLZ3pmbnlOY0ZKZHorb2hjNlYyMlBqWk1FQkhDc0hQTzRhdjJMbFdLCjVZMWZsTCsyYnFUcWJtTy9iamZYMHc0WjFEdW9qUmNPWkY3U0g0TzNRdTJZNy82OWdIN0NwMG5pVkNtNXorUzUKMDExVjZQdk1qcm1pRSt4Vmt4TEhiWUVnb2NiRmhkNURjaU1DWHB2c3VEWm9qYUkzRlJFbUJxaUloS29raTNyYgp3dUVseWE3OGJNd2taMWtycDc2bldzbzQ3LzArNTFpby9XcmlBZHIwY2ptem9uaG83UnFJRTNEQzc3Q0VNa2FnClp2S1NtTDNzZmYrV05Tcm5QbHpuSzE5TkEyejRJbVc5TXN6cVByQ1RRR1AvL0JCdTdTYW16b2ZWTTlmNFBBSXIKRlRwblc2c0dkcEN6UDhFMFdVdTlCK3ZpS3J0Zk0vOXN4bkk5V2hmSlBkckVQMGlaVzN2aHd2Z1FiS2I1RDJPUwpVNG5yVm92NkJXci9CbmhRSzhJWG8xdHEzajhGQ1JJb2xlWE5oa3M0Z25rT2FEc1cyS3RWcXd0SzNpTzNCdlBiCkw1dzBnZExqd01Ma2VrNzJ5NjFYcXo1V3had05obDVZY21CS3VTdm1WU0h2QTY4QlZTYkIKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}],"tLogs":[{"baseURL":"https://rekor.example.com","hashAlgorithm":"sha-256","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFN0QyV3ZncVN6czlqcGRKc09KNU5sNnhnOEpYbQpObW83TTNiTjcrZFFkZHc5SWJjMlIzU1Y4dHpCWncwclNUOEZLY240YXBKZXBjS000cVVwWVVlTmZ3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"rekor-log-id"}],"ctLogs":[{"baseURL":"https://ctfe.example.com","hashAlgorithm":"sha-256","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSnZDSmk3MDdmdjV0TUoxVTJUVk1aK3VPNGRLRwphRWN2amxDa2dCQ0tYYnJrdW1aVjBtMGRTbEsxVjFneEVpeVE4eTZoazFNeEpOZTJBWnJaVXQ3YTR3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"ctfe-log-id"}],"timestampAuthorities":[{"subject":{"organization":"tsa-organization","commonName":"tsa-common-name"},"uri":"https://tsa.example.com","certChain":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6RENDQVhLZ0F3SUJBZ0lVZnlHS0RvRmE3eTZzL1cxcDFDaVRtQlJzMWVBd0NnWUlLb1pJemowRUF3SXcKTURFT01Bd0dBMVVFQ2hNRmJHOWpZV3d4SGpBY0JnTlZCQU1URlZSbGMzUWdWRk5CSUVsdWRHVnliV1ZrYVdGMApaVEFlRncweU1qRXhNRGt5TURNeE16UmFGdzB6TVRFeE1Ea3lNRE0wTXpSYU1EQXhEakFNQmdOVkJBb1RCV3h2ClkyRnNNUjR3SEFZRFZRUURFeFZVWlhOMElGUlRRU0JVYVcxbGMzUmhiWEJwYm1jd1dUQVRCZ2NxaGtqT1BRSUIKQmdncWhrak9QUU1CQndOQ0FBUjNLY0R5OWp3QVJYMHJEdnlyK01HR2tHM24xT0EwTVU1K1ppRG1ndXNGeWs2VQo2Ym92S1dWTWZEOEo4TlRjSlpFMFJhWUpyOC9kRTlrZ2NJSVhsaE13bzJvd2FEQU9CZ05WSFE4QkFmOEVCQU1DCkI0QXdIUVlEVlIwT0JCWUVGSE5uNVIzYjNNdFVkU05yRk80OVE2WERWU25rTUI4R0ExVWRJd1FZTUJhQUZOTFMKNmdubzdPbSsrUXQ1eklhK0g5bzBIaVQyTUJZR0ExVWRKUUVCL3dRTU1Bb0dDQ3NHQVFVRkJ3TUlNQW9HQ0NxRwpTTTQ5QkFNQ0EwZ0FNRVVDSVFDRjBvbG9obnZkVXE2VDcvd1BrMTlaNWFRUC95eFJUakNXWXVobi9UQ3lIZ0lnCmF6VjNhaXI0R1JaYk45YmRZdGNRN0pVQUtxODlHT2h0RmZsNmtjb1ZVdlU9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIwakNDQVhpZ0F3SUJBZ0lVWHBCbVlKRkZhR1czY0M4cDZiL0RIcjFpOElvd0NnWUlLb1pJemowRUF3SXcKS0RFT01Bd0dBMVVFQ2hNRmJHOWpZV3d4RmpBVUJnTlZCQU1URFZSbGMzUWdWRk5CSUZKdmIzUXdIaGNOTWpJeApNVEE1TWpBeU9UTTBXaGNOTXpJeE1UQTVNakF6TkRNMFdqQXdNUTR3REFZRFZRUUtFd1ZzYjJOaGJERWVNQndHCkExVUVBeE1WVkdWemRDQlVVMEVnU1c1MFpYSnRaV1JwWVhSbE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUVLRFBEUkl3RFMxWkN5bXViNnlhbkNHNW1hMHFEakxwTm9uRHZvb1NrUkhFZ1UwVE5pYmVKbjZNKwo1VzYwOGhDdzhud3V1Y01iWFE0MWtOZXVCZWV2eXFONE1IWXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01CTUdBMVVkCkpRUU1NQW9HQ0NzR0FRVUZCd01JTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRk5MUzZnbm8KN09tKytRdDV6SWErSDlvMEhpVDJNQjhHQTFVZEl3UVlNQmFBRkIxbnZYcE5LN0F1UWxiSit5YTZuUFNxV2krVApNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJR2l3cUNJMjl3N0M0VjhUbHRDc2k3MjhzNUR0a2xDUHlTREFTVVN1CmE1eTVBaUVBNDBJZmRsd2Y3VWo4cThOU0Q2WjRnLzBqczB0R05kTFNVSjFkby9Xb04wcz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQmxEQ0NBVHFnQXdJQkFnSVVZWng5c1MxNEVuN1N1SERPSkpQNElQb3BNalV3Q2dZSUtvWkl6ajBFQXdJdwpLREVPTUF3R0ExVUVDaE1GYkc5allXd3hGakFVQmdOVkJBTVREVlJsYzNRZ1ZGTkJJRkp2YjNRd0hoY05Nakl4Ck1UQTVNakF5T1RNMFdoY05Nekl4TVRBNU1qQXpORE0wV2pBb01RNHdEQVlEVlFRS0V3VnNiMk5oYkRFV01CUUcKQTFVRUF4TU5WR1Z6ZENCVVUwRWdVbTl2ZERCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkFiQgpCMFNVOEc3NWhWSVVwaENoQTRuZk93TldQMzQ3VGpTY0lkc0VQcktWbisvWTFIbW1MSEpEalNmbit4aEVGb0VrCjdqcWdycW9uNDhpNHhibzd4QXVqUWpCQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQUQKQVFIL01CMEdBMVVkRGdRV0JCUWRaNzE2VFN1d0xrSld5ZnNtdXB6MHFsb3ZrekFLQmdncWhrak9QUVFEQWdOSQpBREJGQWlCZTVQNTZmb3FtRmNaQVZwRWVBT0ZackFsRWlxMDVDQ3BNTlloNUVqTHZtQUloQUtORjZ4SVY1dUZkCnBTVEpzQXd6alc3OENLUW03cW9sMHVQbVBQdTZtTmF3Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"}]}`

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
	marshalled, err := resources.Marshal(c)
	if err != nil {
		panic("failed to marshal test SigstoreKeys")
	}
	ret.Data[trName] = marshalled
	return ret
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
				LogID:         fmt.Sprintf("%s-logid-%d", prefix, i),
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
			wantLogID := fmt.Sprintf("%s-logid-%d", prefix, i)
			if entry.BaseURL.String() != wantURL {
				t.Errorf("Unexpected BaseURL for %s %d wanted %s got %s", prefix, i, wantURL, entry.BaseURL.String())
			}
			if entry.HashAlgorithm != wantHash {
				t.Errorf("Unexpected HashAlgorithm for %s %d wanted %s got %s", prefix, i, wantHash, entry.HashAlgorithm)
			}
			if string(entry.PublicKey) != wantPublicKey {
				t.Errorf("Unexpected PublicKey for %s %d wanted %s got %s", prefix, i, wantPublicKey, string(entry.PublicKey))
			}
			if entry.LogID != wantLogID {
				t.Errorf("Unexpected LogID for %s %d wanted %s got %s", prefix, i, wantLogID, entry.LogID)
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
