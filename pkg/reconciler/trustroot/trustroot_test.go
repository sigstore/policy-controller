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
	ctfePublicKey   = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJvCJi707fv5tMJ1U2TVMZ+uO4dKG
aEcvjlCkgBCKXbrkumZV0m0dSlK1V1gxEiyQ8y6hk1MxJNe2AZrZUt7a4w==
-----END PUBLIC KEY-----
`
	// This is the LogID for above PublicKey
	ctfeLogID = "39d1c085f7d5f3fe7a0de9e52a3ead14186891e52a9269d90de7990a30b55083"

	fulcioCert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`
	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7D2WvgqSzs9jpdJsOJ5Nl6xg8JXm
Nmo7M3bN7+dQddw9Ibc2R3SV8tzBZw0rST8FKcn4apJepcKM4qUpYUeNfw==
-----END PUBLIC KEY-----
`
	// This is the Rekor LogID constructed from above public key.
	rekorLogID = "0bac0fddd0c15fbc46f8b1bf51c2b57676a9f262294fe13417d85602e73f392a"

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
	marshalledEntry = `{"certificateAuthorities":[{"subject":{"organization":"fulcio-organization","commonName":"fulcio-common-name"},"uri":"https://fulcio.example.com","certChain":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZ3ekNDQTZ1Z0F3SUJBZ0lJSzd4YitycVk0Z0V3RFFZSktvWklodmNOQVFFTEJRQXdmakVNTUFvR0ExVUUKQmhNRFZWTkJNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVFlXNGdSbkpoYm1OcApjMk52TVJZd0ZBWURWUVFKRXcwMU5EZ2dUV0Z5YTJWMElGTjBNUTR3REFZRFZRUVJFd1UxTnpJM05ERVpNQmNHCkExVUVDaE1RVEdsdWRYZ2dSbTkxYm1SaGRHbHZiakFlRncweU1qRXlNRGd3TWpFM05URmFGdzB5TXpFeU1EZ3cKTWpFM05URmFNSDR4RERBS0JnTlZCQVlUQTFWVFFURVRNQkVHQTFVRUNCTUtRMkZzYVdadmNtNXBZVEVXTUJRRwpBMVVFQnhNTlUyRnVJRVp5WVc1amFYTmpiekVXTUJRR0ExVUVDUk1OTlRRNElFMWhjbXRsZENCVGRERU9NQXdHCkExVUVFUk1GTlRjeU56UXhHVEFYQmdOVkJBb1RFRXhwYm5WNElFWnZkVzVrWVhScGIyNHdnZ0lpTUEwR0NTcUcKU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRQzE0MkVqbGcyUXhJd3BOamJhZVcvZnQ5c0gxVFhVNkNXZwpic3ZWcDc3dlJnY2tTbnBNM1JUQy9nd0V3Skh0WCtHT1RyUDlybzZuRkpOM0czaGNGbmFNSExLZEdyb2Y5aUh1Ci93L2xaTHdRelh6VlQrMFp5Wnh5dEhBV0dGQnZtWU00SjMzakg2RGo5UHZxT053dFNCU21aQlBjL0gvOEV2WXMKVXp4UFd1a2hPdG90U0gzVlhEcVo0amw5Nk1MZTArNWcyV2k3TXhSWDQ0WDFSaVBTMTRiYTFFUzUzOGJUaGhjUQo0U01qM3VoYmRzQ0lrY203ZUY0RVkzcEVYUXBYRUVHblpHZndZZ1FyKzZjVDA3WmQvV0RNME5YM0t4SDZxUms5CmdEalBuZmNNdUZiT1RiZkQvbnV2eDZGTlg2T1VyenJaU2dsa0x2Y1BJQlZPVzdMbjQxTEFiN2FYbWJXTEZFSm4KdUxvb1BwWVlyKzZOaG5GRE5HcHNCS0dLci9rdmJReURLS3N0M0NLajlvdFBTMTM2M25pNDFxbm9BN1lXU3F4dwp6NDE4NWRLS2MrWTd5dkpRc1JscjZxRzFzTkxPK2M3N2ZTUzVWWkltek5vekJjUmt1TEpGbFgrV0IwdXpnUVU1CnM0NUlaVytmSzkybmZ1OE1tS2p6SFIraWR5cjRPeWpTMFlTTjNHTWdjMFVQN0s2aFZwaExlZEFwRnB5a0JTRkcKVWdpUFp3clQrbUdTVmdtT1hxNW4xZFFUQ0QxNGxFaDJxdDMvcmZmOHpOYzBDTUFOV3liYU1HQkdRNGJoVlZYZQpSS1l4OXUyUFpqUHY1M3A3WWIvRENkcW5HRUR3L0hDQkRpQ3M0b1llNGRhRTM2eFVvanhEU20zRGFlTkc2OHo5ClJMN2dmVWpBeFFJREFRQUJvMFV3UXpBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFUQWRCZ05WSFE0RUZnUVVmK2xiTlgwV2g0aCtRMFNSdGhSSytLZkxqcUV3RFFZSktvWklodmNOQVFFTApCUUFEZ2dJQkFFaEpqYTBaU0t3WGNhT1hDWVJYVEUwNitKYnBlekk1TGV2QmhtYlJRSzc4OVJxMTBKZUFYYTdtCkVUb1JHbEdGTEgydURUMTFtc0ZLeU0zdjY3S2xFMVNZVmNxS21DbFlmSVZFWUgzTGEwdUkrOXJIWm5XZ2I0QmwKeTFCOHdibEtKemhZUUQ5WjRIL2dzK0JBc29SWDVWb0Z5SWdrTkJrMXAzZnRhVkNia1F2UzBPWXRZczVpdzRlSwpjSTcxL0lzVElUM1pwcGo5UjhJR3Nxd0xLZ3pmbnlOY0ZKZHorb2hjNlYyMlBqWk1FQkhDc0hQTzRhdjJMbFdLCjVZMWZsTCsyYnFUcWJtTy9iamZYMHc0WjFEdW9qUmNPWkY3U0g0TzNRdTJZNy82OWdIN0NwMG5pVkNtNXorUzUKMDExVjZQdk1qcm1pRSt4Vmt4TEhiWUVnb2NiRmhkNURjaU1DWHB2c3VEWm9qYUkzRlJFbUJxaUloS29raTNyYgp3dUVseWE3OGJNd2taMWtycDc2bldzbzQ3LzArNTFpby9XcmlBZHIwY2ptem9uaG83UnFJRTNEQzc3Q0VNa2FnClp2S1NtTDNzZmYrV05Tcm5QbHpuSzE5TkEyejRJbVc5TXN6cVByQ1RRR1AvL0JCdTdTYW16b2ZWTTlmNFBBSXIKRlRwblc2c0dkcEN6UDhFMFdVdTlCK3ZpS3J0Zk0vOXN4bkk5V2hmSlBkckVQMGlaVzN2aHd2Z1FiS2I1RDJPUwpVNG5yVm92NkJXci9CbmhRSzhJWG8xdHEzajhGQ1JJb2xlWE5oa3M0Z25rT2FEc1cyS3RWcXd0SzNpTzNCdlBiCkw1dzBnZExqd01Ma2VrNzJ5NjFYcXo1V3had05obDVZY21CS3VTdm1WU0h2QTY4QlZTYkIKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}],"tLogs":[{"baseURL":"https://rekor.example.com","hashAlgorithm":"sha-256","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFN0QyV3ZncVN6czlqcGRKc09KNU5sNnhnOEpYbQpObW83TTNiTjcrZFFkZHc5SWJjMlIzU1Y4dHpCWncwclNUOEZLY240YXBKZXBjS000cVVwWVVlTmZ3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"0bac0fddd0c15fbc46f8b1bf51c2b57676a9f262294fe13417d85602e73f392a"}],"ctLogs":[{"baseURL":"https://ctfe.example.com","hashAlgorithm":"sha-256","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSnZDSmk3MDdmdjV0TUoxVTJUVk1aK3VPNGRLRwphRWN2amxDa2dCQ0tYYnJrdW1aVjBtMGRTbEsxVjFneEVpeVE4eTZoazFNeEpOZTJBWnJaVXQ3YTR3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"39d1c085f7d5f3fe7a0de9e52a3ead14186891e52a9269d90de7990a30b55083"}],"timestampAuthorities":[{"subject":{"organization":"tsa-organization","commonName":"tsa-common-name"},"uri":"https://tsa.example.com","certChain":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6RENDQVhLZ0F3SUJBZ0lVZnlHS0RvRmE3eTZzL1cxcDFDaVRtQlJzMWVBd0NnWUlLb1pJemowRUF3SXcKTURFT01Bd0dBMVVFQ2hNRmJHOWpZV3d4SGpBY0JnTlZCQU1URlZSbGMzUWdWRk5CSUVsdWRHVnliV1ZrYVdGMApaVEFlRncweU1qRXhNRGt5TURNeE16UmFGdzB6TVRFeE1Ea3lNRE0wTXpSYU1EQXhEakFNQmdOVkJBb1RCV3h2ClkyRnNNUjR3SEFZRFZRUURFeFZVWlhOMElGUlRRU0JVYVcxbGMzUmhiWEJwYm1jd1dUQVRCZ2NxaGtqT1BRSUIKQmdncWhrak9QUU1CQndOQ0FBUjNLY0R5OWp3QVJYMHJEdnlyK01HR2tHM24xT0EwTVU1K1ppRG1ndXNGeWs2VQo2Ym92S1dWTWZEOEo4TlRjSlpFMFJhWUpyOC9kRTlrZ2NJSVhsaE13bzJvd2FEQU9CZ05WSFE4QkFmOEVCQU1DCkI0QXdIUVlEVlIwT0JCWUVGSE5uNVIzYjNNdFVkU05yRk80OVE2WERWU25rTUI4R0ExVWRJd1FZTUJhQUZOTFMKNmdubzdPbSsrUXQ1eklhK0g5bzBIaVQyTUJZR0ExVWRKUUVCL3dRTU1Bb0dDQ3NHQVFVRkJ3TUlNQW9HQ0NxRwpTTTQ5QkFNQ0EwZ0FNRVVDSVFDRjBvbG9obnZkVXE2VDcvd1BrMTlaNWFRUC95eFJUakNXWXVobi9UQ3lIZ0lnCmF6VjNhaXI0R1JaYk45YmRZdGNRN0pVQUtxODlHT2h0RmZsNmtjb1ZVdlU9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIwakNDQVhpZ0F3SUJBZ0lVWHBCbVlKRkZhR1czY0M4cDZiL0RIcjFpOElvd0NnWUlLb1pJemowRUF3SXcKS0RFT01Bd0dBMVVFQ2hNRmJHOWpZV3d4RmpBVUJnTlZCQU1URFZSbGMzUWdWRk5CSUZKdmIzUXdIaGNOTWpJeApNVEE1TWpBeU9UTTBXaGNOTXpJeE1UQTVNakF6TkRNMFdqQXdNUTR3REFZRFZRUUtFd1ZzYjJOaGJERWVNQndHCkExVUVBeE1WVkdWemRDQlVVMEVnU1c1MFpYSnRaV1JwWVhSbE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUVLRFBEUkl3RFMxWkN5bXViNnlhbkNHNW1hMHFEakxwTm9uRHZvb1NrUkhFZ1UwVE5pYmVKbjZNKwo1VzYwOGhDdzhud3V1Y01iWFE0MWtOZXVCZWV2eXFONE1IWXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01CTUdBMVVkCkpRUU1NQW9HQ0NzR0FRVUZCd01JTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRk5MUzZnbm8KN09tKytRdDV6SWErSDlvMEhpVDJNQjhHQTFVZEl3UVlNQmFBRkIxbnZYcE5LN0F1UWxiSit5YTZuUFNxV2krVApNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJR2l3cUNJMjl3N0M0VjhUbHRDc2k3MjhzNUR0a2xDUHlTREFTVVN1CmE1eTVBaUVBNDBJZmRsd2Y3VWo4cThOU0Q2WjRnLzBqczB0R05kTFNVSjFkby9Xb04wcz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQmxEQ0NBVHFnQXdJQkFnSVVZWng5c1MxNEVuN1N1SERPSkpQNElQb3BNalV3Q2dZSUtvWkl6ajBFQXdJdwpLREVPTUF3R0ExVUVDaE1GYkc5allXd3hGakFVQmdOVkJBTVREVlJsYzNRZ1ZGTkJJRkp2YjNRd0hoY05Nakl4Ck1UQTVNakF5T1RNMFdoY05Nekl4TVRBNU1qQXpORE0wV2pBb01RNHdEQVlEVlFRS0V3VnNiMk5oYkRFV01CUUcKQTFVRUF4TU5WR1Z6ZENCVVUwRWdVbTl2ZERCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkFiQgpCMFNVOEc3NWhWSVVwaENoQTRuZk93TldQMzQ3VGpTY0lkc0VQcktWbisvWTFIbW1MSEpEalNmbit4aEVGb0VrCjdqcWdycW9uNDhpNHhibzd4QXVqUWpCQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQUQKQVFIL01CMEdBMVVkRGdRV0JCUWRaNzE2VFN1d0xrSld5ZnNtdXB6MHFsb3ZrekFLQmdncWhrak9QUVFEQWdOSQpBREJGQWlCZTVQNTZmb3FtRmNaQVZwRWVBT0ZackFsRWlxMDVDQ3BNTlloNUVqTHZtQUloQUtORjZ4SVY1dUZkCnBTVEpzQXd6alc3OENLUW03cW9sMHVQbVBQdTZtTmF3Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"}]}`

	// validRepository is a valid tar/gzipped repository representing an air-gap
	// TUF repository.
	validRepository = `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`

	// rootJSON is a valid base64 encoded root.json for above TUF repository.
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDIzLTA2LTExVDAzOjM5OjE0WiIsCiAgImtleXMiOiB7CiAgICIyNmY4MDQ1ZWEzOTI3YTJmZmYyNGU5MDRkMjgwMWFhMTExNzY2YmJhMWU1ZjYwZTQwOTVhOGU4YmJmMmM3MmQ2IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJmZTg3Mjk3ZTEyOWQwYmU3NGEyYTdjY2Y4ZTk1N2E1NmIyYWE0ZjQ1ZWQ5NWNhNTJiNmI5ZjUxODA3MTEwNWUyIgogICAgfQogICB9LAogICAiMzJmNzM1ZGUyNTE3MTQ4NzRjMzAyM2VhMjc3M2RlNzZiMjY3NzY0OWEwYTI5Yzg1N2RlOTgzMmI0NzY5MTA3YSI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiMmJkZGVmNDgzOWJhNTdlZjBlNGY4NzA2YzIyNzM5OWVjY2E5YTk3YzZmMjI3NjA0YzI1Njk5NjgzNmMxOTkxMyIKICAgIH0KICAgfSwKICAgImEzZTRjN2FiMjgyNjRmNzk2YzA2OTc5MGE2MjljMDA0MDFkNjU2N2RmMWI3NGM3MDA5OTVmOTVkODY2MmQyYjEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogImUwYjE3MTBmMjJmMzFlNTgzN2EyYmVjNDRlYzE4ZjZmMjQzOGI0NTY3NDRmNzU5ZmE3YTRkZWI3YjRjM2JhMmEiCiAgICB9CiAgIH0sCiAgICJhYzkxYzYwODVkNjMxOGYxMTgyN2U5MmQzOGVmNTBiYzdhZDJlNGNkMDM1YjI1ODZjMDZjNTYwZTBhYWJiMjdkIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI4ZTY3Y2I1N2E4NmE0MTRjZGRlZjZiZDhmZTAwODM1NzIyOTNkY2ZmOWFlYTNlNTc4MDg4Y2MyNmEzNWNiMDgzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiYWM5MWM2MDg1ZDYzMThmMTE4MjdlOTJkMzhlZjUwYmM3YWQyZTRjZDAzNWIyNTg2YzA2YzU2MGUwYWFiYjI3ZCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICIyNmY4MDQ1ZWEzOTI3YTJmZmYyNGU5MDRkMjgwMWFhMTExNzY2YmJhMWU1ZjYwZTQwOTVhOGU4YmJmMmM3MmQ2IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiMzJmNzM1ZGUyNTE3MTQ4NzRjMzAyM2VhMjc3M2RlNzZiMjY3NzY0OWEwYTI5Yzg1N2RlOTgzMmI0NzY5MTA3YSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiYTNlNGM3YWIyODI2NGY3OTZjMDY5NzkwYTYyOWMwMDQwMWQ2NTY3ZGYxYjc0YzcwMDk5NWY5NWQ4NjYyZDJiMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiYWM5MWM2MDg1ZDYzMThmMTE4MjdlOTJkMzhlZjUwYmM3YWQyZTRjZDAzNWIyNTg2YzA2YzU2MGUwYWFiYjI3ZCIsCiAgICJzaWciOiAiZjk2MzI4OWJlZDI4OWFmMmRhMDAyMzJmOWE5ODJhZDY5MTdkYTc4ZjMwNmZjZTYwZjcxN2VmNzgwZTBhMGY1YzI1OGYzNDFiZTE3OGQ0N2UzZWEzOTUzYWFjMmJiZTgxOGUxMjJkNTAwZmIwMjJiMmU1YWRkNDNmNzY3YTU3MGMiCiAgfQogXQp9`

	// These are the public keys from an airgapped TUF repository.
	/* TODO(vaikas): Uncomment and test these make the roundtrip
		tufCTFE = `-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJvCJi707fv5tMJ1U2TVMZ+uO4dKG
		aEcvjlCkgBCKXbrkumZV0m0dSlK1V1gxEiyQ8y6hk1MxJNe2AZrZUt7a4w==
		-----END PUBLIC KEY-----
	`
		tufFulcio = `-----BEGIN CERTIFICATE-----
		MIIFwzCCA6ugAwIBAgIIK7xb+rqY4gEwDQYJKoZIhvcNAQELBQAwfjEMMAoGA1UE
		BhMDVVNBMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNp
		c2NvMRYwFAYDVQQJEw01NDggTWFya2V0IFN0MQ4wDAYDVQQREwU1NzI3NDEZMBcG
		A1UEChMQTGludXggRm91bmRhdGlvbjAeFw0yMjEyMDgwMjE3NTFaFw0yMzEyMDgw
		MjE3NTFaMH4xDDAKBgNVBAYTA1VTQTETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQG
		A1UEBxMNU2FuIEZyYW5jaXNjbzEWMBQGA1UECRMNNTQ4IE1hcmtldCBTdDEOMAwG
		A1UEERMFNTcyNzQxGTAXBgNVBAoTEExpbnV4IEZvdW5kYXRpb24wggIiMA0GCSqG
		SIb3DQEBAQUAA4ICDwAwggIKAoICAQC142Ejlg2QxIwpNjbaeW/ft9sH1TXU6CWg
		bsvVp77vRgckSnpM3RTC/gwEwJHtX+GOTrP9ro6nFJN3G3hcFnaMHLKdGrof9iHu
		/w/lZLwQzXzVT+0ZyZxytHAWGFBvmYM4J33jH6Dj9PvqONwtSBSmZBPc/H/8EvYs
		UzxPWukhOtotSH3VXDqZ4jl96MLe0+5g2Wi7MxRX44X1RiPS14ba1ES538bThhcQ
		4SMj3uhbdsCIkcm7eF4EY3pEXQpXEEGnZGfwYgQr+6cT07Zd/WDM0NX3KxH6qRk9
		gDjPnfcMuFbOTbfD/nuvx6FNX6OUrzrZSglkLvcPIBVOW7Ln41LAb7aXmbWLFEJn
		uLooPpYYr+6NhnFDNGpsBKGKr/kvbQyDKKst3CKj9otPS1363ni41qnoA7YWSqxw
		z4185dKKc+Y7yvJQsRlr6qG1sNLO+c77fSS5VZImzNozBcRkuLJFlX+WB0uzgQU5
		s45IZW+fK92nfu8MmKjzHR+idyr4OyjS0YSN3GMgc0UP7K6hVphLedApFpykBSFG
		UgiPZwrT+mGSVgmOXq5n1dQTCD14lEh2qt3/rff8zNc0CMANWybaMGBGQ4bhVVXe
		RKYx9u2PZjPv53p7Yb/DCdqnGEDw/HCBDiCs4oYe4daE36xUojxDSm3DaeNG68z9
		RL7gfUjAxQIDAQABo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB
		/wIBATAdBgNVHQ4EFgQUf+lbNX0Wh4h+Q0SRthRK+KfLjqEwDQYJKoZIhvcNAQEL
		BQADggIBAEhJja0ZSKwXcaOXCYRXTE06+JbpezI5LevBhmbRQK789Rq10JeAXa7m
		EToRGlGFLH2uDT11msFKyM3v67KlE1SYVcqKmClYfIVEYH3La0uI+9rHZnWgb4Bl
		y1B8wblKJzhYQD9Z4H/gs+BAsoRX5VoFyIgkNBk1p3ftaVCbkQvS0OYtYs5iw4eK
		cI71/IsTIT3Zppj9R8IGsqwLKgzfnyNcFJdz+ohc6V22PjZMEBHCsHPO4av2LlWK
		5Y1flL+2bqTqbmO/bjfX0w4Z1DuojRcOZF7SH4O3Qu2Y7/69gH7Cp0niVCm5z+S5
		011V6PvMjrmiE+xVkxLHbYEgocbFhd5DciMCXpvsuDZojaI3FREmBqiIhKoki3rb
		wuElya78bMwkZ1krp76nWso47/0+51io/WriAdr0cjmzonho7RqIE3DC77CEMkag
		ZvKSmL3sff+WNSrnPlznK19NA2z4ImW9MszqPrCTQGP//BBu7SamzofVM9f4PAIr
		FTpnW6sGdpCzP8E0WUu9B+viKrtfM/9sxnI9WhfJPdrEP0iZW3vhwvgQbKb5D2OS
		U4nrVov6BWr/BnhQK8IXo1tq3j8FCRIoleXNhks4gnkOaDsW2KtVqwtK3iO3BvPb
		L5w0gdLjwMLkek72y61Xqz5WxZwNhl5YcmBKuSvmVSHvA68BVSbB
		-----END CERTIFICATE-----
	`
		tufRekor = `-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEenlW+tMJ9ymhl858kKiD14CC06x9
		r36rTqTSiLYrdl2ZVE3mOD/KcbyBZM1/RHVKx/g1r3d0YSoVCKbF4DAvcQ==
		-----END PUBLIC KEY-----
	`
	*/

	// this is the marshalled entry for when we construct from the repository.
	marshalledEntryFromMirrorFS = `{"certificateAuthorities":[{"subject":{"organization":"","commonName":""},"uri":"","certChain":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZ3ekNDQTZ1Z0F3SUJBZ0lJSzd4YitycVk0Z0V3RFFZSktvWklodmNOQVFFTEJRQXdmakVNTUFvR0ExVUUKQmhNRFZWTkJNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVFlXNGdSbkpoYm1OcApjMk52TVJZd0ZBWURWUVFKRXcwMU5EZ2dUV0Z5YTJWMElGTjBNUTR3REFZRFZRUVJFd1UxTnpJM05ERVpNQmNHCkExVUVDaE1RVEdsdWRYZ2dSbTkxYm1SaGRHbHZiakFlRncweU1qRXlNRGd3TWpFM05URmFGdzB5TXpFeU1EZ3cKTWpFM05URmFNSDR4RERBS0JnTlZCQVlUQTFWVFFURVRNQkVHQTFVRUNCTUtRMkZzYVdadmNtNXBZVEVXTUJRRwpBMVVFQnhNTlUyRnVJRVp5WVc1amFYTmpiekVXTUJRR0ExVUVDUk1OTlRRNElFMWhjbXRsZENCVGRERU9NQXdHCkExVUVFUk1GTlRjeU56UXhHVEFYQmdOVkJBb1RFRXhwYm5WNElFWnZkVzVrWVhScGIyNHdnZ0lpTUEwR0NTcUcKU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRQzE0MkVqbGcyUXhJd3BOamJhZVcvZnQ5c0gxVFhVNkNXZwpic3ZWcDc3dlJnY2tTbnBNM1JUQy9nd0V3Skh0WCtHT1RyUDlybzZuRkpOM0czaGNGbmFNSExLZEdyb2Y5aUh1Ci93L2xaTHdRelh6VlQrMFp5Wnh5dEhBV0dGQnZtWU00SjMzakg2RGo5UHZxT053dFNCU21aQlBjL0gvOEV2WXMKVXp4UFd1a2hPdG90U0gzVlhEcVo0amw5Nk1MZTArNWcyV2k3TXhSWDQ0WDFSaVBTMTRiYTFFUzUzOGJUaGhjUQo0U01qM3VoYmRzQ0lrY203ZUY0RVkzcEVYUXBYRUVHblpHZndZZ1FyKzZjVDA3WmQvV0RNME5YM0t4SDZxUms5CmdEalBuZmNNdUZiT1RiZkQvbnV2eDZGTlg2T1VyenJaU2dsa0x2Y1BJQlZPVzdMbjQxTEFiN2FYbWJXTEZFSm4KdUxvb1BwWVlyKzZOaG5GRE5HcHNCS0dLci9rdmJReURLS3N0M0NLajlvdFBTMTM2M25pNDFxbm9BN1lXU3F4dwp6NDE4NWRLS2MrWTd5dkpRc1JscjZxRzFzTkxPK2M3N2ZTUzVWWkltek5vekJjUmt1TEpGbFgrV0IwdXpnUVU1CnM0NUlaVytmSzkybmZ1OE1tS2p6SFIraWR5cjRPeWpTMFlTTjNHTWdjMFVQN0s2aFZwaExlZEFwRnB5a0JTRkcKVWdpUFp3clQrbUdTVmdtT1hxNW4xZFFUQ0QxNGxFaDJxdDMvcmZmOHpOYzBDTUFOV3liYU1HQkdRNGJoVlZYZQpSS1l4OXUyUFpqUHY1M3A3WWIvRENkcW5HRUR3L0hDQkRpQ3M0b1llNGRhRTM2eFVvanhEU20zRGFlTkc2OHo5ClJMN2dmVWpBeFFJREFRQUJvMFV3UXpBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFUQWRCZ05WSFE0RUZnUVVmK2xiTlgwV2g0aCtRMFNSdGhSSytLZkxqcUV3RFFZSktvWklodmNOQVFFTApCUUFEZ2dJQkFFaEpqYTBaU0t3WGNhT1hDWVJYVEUwNitKYnBlekk1TGV2QmhtYlJRSzc4OVJxMTBKZUFYYTdtCkVUb1JHbEdGTEgydURUMTFtc0ZLeU0zdjY3S2xFMVNZVmNxS21DbFlmSVZFWUgzTGEwdUkrOXJIWm5XZ2I0QmwKeTFCOHdibEtKemhZUUQ5WjRIL2dzK0JBc29SWDVWb0Z5SWdrTkJrMXAzZnRhVkNia1F2UzBPWXRZczVpdzRlSwpjSTcxL0lzVElUM1pwcGo5UjhJR3Nxd0xLZ3pmbnlOY0ZKZHorb2hjNlYyMlBqWk1FQkhDc0hQTzRhdjJMbFdLCjVZMWZsTCsyYnFUcWJtTy9iamZYMHc0WjFEdW9qUmNPWkY3U0g0TzNRdTJZNy82OWdIN0NwMG5pVkNtNXorUzUKMDExVjZQdk1qcm1pRSt4Vmt4TEhiWUVnb2NiRmhkNURjaU1DWHB2c3VEWm9qYUkzRlJFbUJxaUloS29raTNyYgp3dUVseWE3OGJNd2taMWtycDc2bldzbzQ3LzArNTFpby9XcmlBZHIwY2ptem9uaG83UnFJRTNEQzc3Q0VNa2FnClp2S1NtTDNzZmYrV05Tcm5QbHpuSzE5TkEyejRJbVc5TXN6cVByQ1RRR1AvL0JCdTdTYW16b2ZWTTlmNFBBSXIKRlRwblc2c0dkcEN6UDhFMFdVdTlCK3ZpS3J0Zk0vOXN4bkk5V2hmSlBkckVQMGlaVzN2aHd2Z1FiS2I1RDJPUwpVNG5yVm92NkJXci9CbmhRSzhJWG8xdHEzajhGQ1JJb2xlWE5oa3M0Z25rT2FEc1cyS3RWcXd0SzNpTzNCdlBiCkw1dzBnZExqd01Ma2VrNzJ5NjFYcXo1V3had05obDVZY21CS3VTdm1WU0h2QTY4QlZTYkIKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}],"tLogs":[{"baseURL":"","hashAlgorithm":"","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFZW5sVyt0TUo5eW1obDg1OGtLaUQxNENDMDZ4OQpyMzZyVHFUU2lMWXJkbDJaVkUzbU9EL0tjYnlCWk0xL1JIVkt4L2cxcjNkMFlTb1ZDS2JGNERBdmNRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"9fc88cc14a684bb689c984a1d159f2d8b29ee71440c95ccc734e3e4024f7f210"}],"ctLogs":[{"baseURL":"","hashAlgorithm":"","publicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSnZDSmk3MDdmdjV0TUoxVTJUVk1aK3VPNGRLRwphRWN2amxDa2dCQ0tYYnJrdW1aVjBtMGRTbEsxVjFneEVpeVE4eTZoazFNeEpOZTJBWnJaVXQ3YTR3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==","logID":"39d1c085f7d5f3fe7a0de9e52a3ead14186891e52a9269d90de7990a30b55083"}],"timestampAuthorities":null}`

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
