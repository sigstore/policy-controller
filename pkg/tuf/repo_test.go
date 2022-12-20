// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tuf

import (
	"bytes"
	"encoding/base64"

	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf"
	"knative.dev/pkg/logging"
)

const (
	fulcioRootCert = `-----BEGIN CERTIFICATE-----
MIICNzCCAd2gAwIBAgITPLBoBQhl1hqFND9S+SGWbfzaRTAKBggqhkjOPQQDAjBo
MQswCQYDVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlw
cGVuaGFtMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMI
dGVzdGNlcnQwHhcNMjEwMzEyMjMyNDQ5WhcNMzEwMjI4MjMyNDQ5WjBoMQswCQYD
VQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlwcGVuaGFt
MQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMIdGVzdGNl
cnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRn+Alyof6xP3GQClSwgV0NFuY
YEwmKP/WLWr/LwB6LUYzt5v49RlqG83KuaJSpeOj7G7MVABdpIZYWwqAiZV3o2Yw
ZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU
T8Jwm6JuVb0dsiuHUROiHOOVHVkwHwYDVR0jBBgwFoAUT8Jwm6JuVb0dsiuHUROi
HOOVHVkwCgYIKoZIzj0EAwIDSAAwRQIhAJkNZmP6sKA+8EebRXFkBa9DPjacBpTc
OljJotvKidRhAiAuNrIazKEw2G4dw8x1z6EYk9G+7fJP5m93bjm/JfMBtA==
-----END CERTIFICATE-----`

	ctlogPublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAu1Ah4n2P8JGt92Qg86FdR8f1pou43yndggMuRCX0JB+bLn1rUFRA
KQVd+xnnd4PXJLLdml8ZohCr0lhBuMxZ7zBzt0T98kblUCxBgABPNpWIkTgacyC8
MlIYY/yBSuDWAJOA5IKi4Hh9nI+Mmb/FXgbOz5a5mZx8w7pMiTMu0+Rd9cPzRkUZ
DQfZsLONr6PwmyCAIL1oK80fevxKZPME0UV8bFPWnRxeVaFr5ddd/DOenV8H6SPy
r4ODbSOItpl53y6Az0m3FTIUf8cSsyR7dfE4zpA3M4djjtoKDNFRsTjU2RWVQW9X
MaxzznGVGhLEwkC+sYjR5NQvH5iiRvV18q+CGQqNX2+WWM3SPuty3nc86RBNR0FO
gSQA0TL2OAs6bJNmfzcwZxAKYbj7/88tj6qrjLaQtFTbBm2a7+TAQfs3UTiQi00z
EDYqeSj2WQvacNm1dWEAyx0QNLHiKGTn4TShGj8LUoGyjJ26Y6VPsotvCoj8jM0e
aN8Pc9/AYywVI+QktjaPZa7KGH3XJHJkTIQQRcUxOtDstKpcriAefDs8jjL5ju9t
5J3qEvgzmclNJKRnla4p3maM0vk+8cC7EXMV4P1zuCwr3akaHFJo5Y0aFhKsnHqT
c70LfiFo//8/QsvyjLIUtEWHTkGeuf4PpbYXr5qpJ6tWhG2MARxdeg8CAwEAAQ==
-----END RSA PUBLIC KEY-----`

	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF6j2sTItLcs0wKoOpMzI+9lJmCzf
N6mY2prOeaBRV2dnsJzC94hOxkM5pSp9nbAK1TBOI45fOOPsH2rSR++HrA==
-----END PUBLIC KEY-----`

	// validRepository is a valid tar/gzipped repository representing an air-gap
	// TUF repository.
	validRepository = `H4sIAAAAAAAA/+y8WZPayLY93s98Codf+Z8m56EjzoMEAlRCVIkZ/nGjI0cxQzEJuHG++y+o8mx3u++x293n3toPLkglyq2l1Nprp3J757ab/eyw2V1++tMMAAA4pU9/AQCf/n36DAkmFFGACfoJQIwg++kV/fNcem/H/UHtfgJgt9kcfq/f145/enH/Ifb+/lfgz7dr/Hm+36y/7xg3PBghv3X/CQLok/tPMQQ/vfohIP4fv///XXr1ej/L186+/uXVf5devXr96+Gyda9/efX6dsWv/79b037rzK8nt9vPNuvbEfgzeD7wvg0+fXfn7Wzn9rc+CCD8D8D+AWEP4F+w/AWSyfOPFu6yfzPYq9eIeQEIdQpLxBXy3iPiJCAWCQCVghByxrRW0FHPgCNAUiWc0Nojw5Flb0/0dNq3njuLKIXyabib+2bqVl86sHCXmf11qvbTX9Uy3+xmh+nq5tr//3T41ev9VCHK3vR++kohev307b/en+Kklu+8ePV6e9TLmbkN5p3gSHIHkbRAO04UUtwYL5ykXFGmkVLEE+qspEZRpJmWnkIBOISAujcD/ev277+eRnuNkeeYWoco5JAITgwGCDuFOMfWcaYR45wRqYBC0gjKrZMCI004kxBw9TcGC2lrnScCS60odx444gUHzCDEsZTOGCWV5IZ5hDgDxCDKpGQCMwOlhPhzsBR2xHClkUCMeC6ZAUxyCRRD0gBAALSMMm491JwYDoCU1EtqBWPIIg3/xmA5oCGHwCPkMXRUYK6QdoYQZ6DwzCOChSaUcUI8p9Irroh1mmtisFZIfQEsI6FhQFDLMBQeQoG4k8hi4TwF2nBlkSPGAkw1ouKGpaEMOKCU1ojbvzFYwjFuNOVKMEUgMbd5xrQV3gEgMOUISWyN91I5hR3lAghhDGIKU6OB+Ghmld4A9nq3Wbr3JPbElB8iMLMf+v/N4H50qYfpzu2nm+UNc/jBLdyv1XY//V1Hvpls/5AjB7XL3WH/O358M4/9MT9mK7c/qNX2927Nt5LEVzx5N2HMZr2f7Q9uffj1gxvl1XLvSk9dnqKwOhyfw+fNv+e59eTybR5/8yx6M01m+VNwkgwjIbWzSEjlkVUAIIy8VFIgZZmE3CouPAbMG8eA55A7z8XtfMBTg6jwmEDtIBeWcIdvk4pipQzS2gkoHETIUgC8Bghp5KiylmDPGVeUA3MD7l+lV/9V+tdfrYD+b9sH+v9PUv//lv6HFL7o/x9hL/r/Rf//HcB60f8v+v9F/7/o/xf9/6L/X+zH2Qf6/+28/O45wFf0P4T0U/3PAGIv+v9H2O/o/3c89SfkACt3eKdG3waMp3n3nquXbp0fpq9/eYUwZ28I9qYR3sfd91rgl1evOaXUOKI5AYBq7ohwRgvmJBXaKEKIEF44JJzV0inLPbkpSUqYAoxIx29sBaWSAN+igVWEIqGtRJYh7QUU2hAOqDVEWEoZxZRBQDW0WEplufFvZMIbRz8A5V0c+IM8/81B+mOeh4Z4rrwUXGDpmPbMeQ+NYhAJYpEyHnPjlBDAemA1dBZKKqQDQnGtlbqpS8uMklgC6Cwz9hYiAcAYcmCwJBAhRC31XglLAeVOOgKfVJXBQL7w/N/bPuD/N4/h9x/jf/7+nzDGX97//wj7/P5XzMG7n7dH/d3G+Er8B4h9Fv8x5y/x/0fYP24WRo24/eqhH7bi6qskGj81ltL6ooiKcTPZTOLrHFSDbBy/+VwLMlPL8iC6O1XvZhxwf6KH9A72UW+QTsrHe2KTRklF5jRfVhd5WE1Gerc4riYDsAK2u0zgAObnaHbJxIVNFzA937UdCia7Sf/AFSn++c/Skw9Ru/aZW381Yv+77AvPvz8uzWzz6wn+bHaHn7du9a1jfG39H0D48fOPAET45fn/EfbB81+NOr24HleDXvSGAOK4Xlyr1YAd86CIwyCP44SfdXn3OCZ5VNSy8d2NEKYn0w6yqBVmQeHnUZoGm0YA+1EpnKa1waAdpp20iLJxbZBlcVRsa+PheTtZyYteLadpZ1zUg6djzaiAvfGQ5J313VSv2tuSQe3TBx3uogLAdi3Pe8P6RaEBiOttkGakqD0f70RFH7avMW7Xokkamkbp5kZ1mma9xvJoR3neWUmoV52pbSxPeh64egEu6Ty6pLW8SOcRbvfq6qnt+txWetuYNsm5VguSMG8PwmDcC+Cgl/WiXhpGT9daDdMkQ/W9Gk5OZkW34140TMPs2YPwnLb7qH6Mo8llPKRzNWrP9fW5w9OPO2m73ctIHMGpWR2Wthr2bC26T4Pi+QRRJ623e+bSvmbnRi8YPXux6UXReavXAxJHk5Md0sV41NlqRIo8j2dpABrV7mOj1I01rmVRGGT9ICBxtVYEtw5JsImrQVaFBEXzZY6yc1xs23Ot3LDiD3LfhL1Rn1WHeUnvT4Mt56dObhbd9TbFnV61khdRcdc8jMqN+97uQe42bF2/a+MGnpr6WqXNVmIbu42Xs+axVCkqy0mryK6j66BXBpPL5Hw5NINhox6eVuOU3GE8b7LaXD6cHu/bxaEbdleT8MFUmhURncb7Uv96fhgeF9P7w+bQbeLBqPY4IfOlZGnLgTLN0XDG03NnRMgIdmYPXUi0glGXYqF706nJSqSbzvFxqu2+Gi/Mirs6icZ4G42y7SiKGutJwxfjPNuVmekBPrGVYS0F7RFOzk322FnIUl6bP6y9SY91fd/TvlZZH09nVm+P2H1/d91Nuvly0TqZhzgc3A95a01gK9BcjVZ62KpHd+vSsbXZPGzH412Ztafreq3d2O7DpJHsKouTzi61JNkfcDWZy83hoQsxw+sZgY/rTcDHw+7juShdCRTUJokpj/nldJftO8sde2zAfbt1Xzac+26XDibx6treXEPTWRxbd/XlqDwMwfGaZ31a2hMaT4Zln0i09keRrpL5tdkpz+xlR+4v8y4Yd9u4keYG9B94wqaD7bTlbLCtby+LsFtvlPr57GFS7HrlVaM7yFf3o0e6hjbrVWuQLKMpejzgys57cW0bUE2D9vCiVdoIGxnR08Fg5EqdZHyWR/QwmT+cKN7ysa7UqvZx3YhqRaVZDWuz6p5sxo5YFWF27m/m51p3hWvKtRtMXGWp0+K578+DcxbXgiwIN6BfZNfg/vY8NDMRBl5EYZDepEoR5ePaoAN6QdashEFehHkUlio3GusF9vkHJKrnWd+Xl7o9AsMpmZYz0O0cpp2knPjW/PFziiuFWVDL8zgMoundXIFJNylGRt2PquPOqBcBVr7TW3eNacudwulKd7KEC9l5hODOBSPFV6Wot+k0lo16q4mOtR6Eq309uaT4xHiyjGB3PDCPyaq6HPt4EI2buKXAMS7LXXOyHuaahMvSBYai0Mvk7jodZzU5Ic1Kvi+HwX7TGdHBpn6J80U7XMAt9gc1qOpFduqC+/FhvKezgrikZGIOK/G+F/fwZLudy46IG/vHopXkV7++tE39zl7Lm6lhA4Qe5pM0CpvVffPhnqgTai2HSYmOoV+2ykg/9h716r6i534ECjKBteNm3jH3kzrvNsk9zo5ozCtM5k1e3YL1bFBd0Wu5S0sAwgF7OKXz3WoWlc+DxbnV1OMo3xhdn1paM7O0Otqe9sfaZDNXMa53olX4OIunyWYxwztdKo7R8qK40GmxmMDFbsvZerjfEF4BZQpnm8pwNwvsDpj56rpZTze88xhHuFblvBqlC5WXJqeku2rhvfflYbu7Wz8sr+sEynaAriReDWW6vz4+7Kq9rPFQqYThkXfV6rrxg1R68hDEu1K9t10P2b5ht9Xrg4jAsH+UYfk0S3YHn1bk/ryO5XDq7x7sLnoAs8kQn6bFKc90omkN3XdLfbLeDTYnFg53lXA9zRIRjzbw8Ijnol7txJulG7Wniz3J14t7VdsPUXIYPBaHBM/ucXh60KUWLUBuW/MibS3cgqMLg6PHKx2eJ0V7uqRjswqTY/e0GnSbp4CJcNDV4XtV/Vmw/6uFyIv9JfYF/b9zi83uey4A/Bv5PwMv+/9/iH1j/u/Wy2H5kN7Jy2q6FFQsklkNkmoVsLMs7TDb9R573VlrvLNLNBlEeHVfqyRGX8JJCiud5iA5V3K4wxaMu5tBNdF1UgtOJnvJ/3+UfeH5P+zVr7P1we1Wzs7Uwf0KvnEh4Gvv/xAjn+T/CICX/P+H2Ffy/xDMq9VgNHub//e1S2ybXoZdXdupx0o2EmZYbaJudu0X1fwdQURBERel5E0O+yYLr+uGnI+Hxbk+D/rPKWzaqw06S4OzfFBvh3H97qRxVjSnpp3O43MpnQckrcWXdi+9Dm+N1/j8pu2a1tLrcB4UH+T/SVQM9hq1p7oWuTR8kzwH53QwaAyuthr2+yDKu0MKJqO7w2TY2Y5HneXv8Vzp3UInqbblaFjhUZ6k+zaI1mJdILafNMSG4yFvpLigZnou1lKUH5fz1U5GxbC9LpHJoO5VYZk2d0HO+Hq+vlzvdYWvj6vksU3S5rioPacqD8+pSlYL8qiRhukNN1u6y7KnFZVqdd8Isn49LNI4DcTTwaiIwkqR1dMgveU+RTN7OtF9GI6jetSadxK+LoXLgZEkeSgvRjCSYIH283EaPp8gLrJxGqqgHtWn+WRZbvKRS+6cFmGc2st1v0lqqPQ8+mOjmxL5lF2BPEijfjUO2Ab3angn7hbjtG1mTX9N5u27qaraQE4qx+lqIwc9UJKtYRLMoiDf4fDe2h05RAO1nhrUHKlaZhJavRIzCvsPkKAu7qSz8vifL1L1h9hv8P/SKf+9ln+/zv/0U/4HAL3ovx9iX+P/a+/G/8k7/g+TS5/LPJ0N4Omh2YiTZtrK+YBcVf45/6e/wf/NeWDe8n/9Q/6PlkfbGFz0cLBQwzooTXqfLtHGOL22Vb0A17T3ti0tbm1pLTjX5kH6dm00HJ5PpTGq79MOKZrPAaIWnQf9yagN4nqnl3XDvhrCpcGdqR6FW70yxbAX9MLcPE4X8/uHLA5LYZ6/+ZKGYdGuBkHvXDP1wOgrdNGxXL6K1uaut3ho1lB7dYr3ncO+v/GhKuxUL3ankuksOkbNGmcWZyk4NZq9TrWStXUm0mnv2J43M9zeb5LzBm0KVft8KasUkuBjXk9Bd1Nlg8poJC+bAN13XKpa0fUEZuvPab01L92CwJdjwPip8132FES+EGSeab/0nvcXQRqNq3FW7XSQHiUNMzpCtJnNWrPV1CuV9rdVcZmoRiXZDmZ1OlnXOkE8LQWtzbg+qiXXNG2F82HkYHu4GW+CfrSpd/R4cOabwerqDBZh44X3f6j9Bv8/1QL9KP6HmH/G/5y88P+PsK/x/7JWrQa9x3f836TLSyFUvbEbd8/HMD7Mp0Vv2CiKvPhr9P/mN/T/+7dvwTltf6j/+yt5srVwclPY4eVZ1t4U91uJGxRRMwBxEN4vt6UrbwZp+pivL9Nld986tLPuvtPpNgwfrWZ3WdbpVho9dKHT7qnW3Se7sIzvDpdRMb4r7npB7kvZYbCn1eNwEZUdcqat2sN5Ng+DNCBP7Ft7lvA3wMJwHjw88X8nfeb/XnDLQJqVNATPnfNsGIadcDxuTPy0DPFsNlpVgm6tafY8qeZyHiTvI9YtkWjHpaAW1m/qu3xeJ9mhn0yTvCNgHdDVTp3oWLXStPnwuGcxkfd05hLZjatxuE53w96UgeWi1Onsg362Y4/zVnk0undwEkfpfaOMYPV6KKv9C2X/59rn/P/9S0C/tv+Dwk/3/1FGXuo/f4j9zv7vt3U8f8L2709KhF6/3XL4hd3fkIuvb/6GQBqOISBUGEid9lpbgxFQ3ikMLVGcOyooAgRC6rw3GGqDHKKOYok1V5gzai3WEHhqOTfMCmMs09Bpg53GVHN+m6HYWgKkIQIQZo3EAjnjMft487c57g+b1YeOzvL9YbNz75tevT7uVf4Ec7VXj97Wtr16vT+ow/EJvcAcZif3/shxN7s1Pw/1XI/2UQnfZ9u2vrSVHlD+dTQlJhZTg6iikgHphcCccSGM9sYo7CR3AmCllTfMUgW50YoIARyRXGoKpROOYoOJwchwJ5VA0ujbL42wQHKircVAIOMdItxq4ihVzhPHuTOGoG9Bs/6EwvfA891rsH93UjLqIeQAOIWREBBx5SCSRHJmkLWWKoExgxRCjY2EkFKJGZJeI6URd4Ror4UC2GFknQWOOwURFMRwRCgTTALEtZMCK0A5pZZAiiW1DFFunaUKfwuMndvFfw8Uf/tlwhdgZRJ9HVahEVQWMUCxYZYJAAXWkDMhsPMUQa6E0eKGG7UMGM+8kIJRDjlBXCuOpQQMeSic5kg6bLiXzCJMoaCO+RtLGKWd8gw6IL13BngELFAUSeqR/xZYe93ge4H64Qrdl6AU5OtQIg201dZKaDwgxFIhoIQWAyaE4JBD7jkl1HKkASSCSUO819wBCxi0SghrCOBaMSGo9hoJYbiVkBsinWFKaAyp4wh4pLyA0iOBlLSQKKA0NEL9TaD8MNn9EpTgD3CmBUwoqo1DmBlBIBGQaWGgkIJ7IZSTDhgIDQWKAYcYlcghZJ3XwHCLkDHIKm2E0ZJJe2NURhE13DqFBaSMa8OMVRxoxG/hR2HEuLaEYMgcAN/0sH8zlP+D6qZvLv39uLoJWG+NpJgJ7JSQEkptOTWIeKAlowhBqbBHhACMOdCCWMMAx/IGNCGIKM2s5gZIhpWymBPjiOPaCe2AlJQSYxh0XmJJEAIEGEwdMUJ6CJ0C+j+/uulD/f+2Xvp7ZwBfXf+h+NP9H5C/vP/9IfZ7+v9d/fyfXQD6UeXxlxgY/gG5xQFFykGlCRbIU4SF0JZyyj0xnEGEBSASQwK8pgZY4rQiiFiPgAdIE0wtsEwDqjT2jHmPPBYASgEJ51RKgBVHGnLJhaEcM0golEQyrxGQmFD63QpAv/n/JPiIIjEHyHpMvVRQUa25MRoSDAgk1FuFNJbUcaEd80pqq6kRUgDDueWOam5uV46so1oo4ZRUxnMLAYAKC8ANRpAghW6aFAvgBSdYCCYUMMo7QgDg//kU+WIv9mIv9r/S/l8AAAD//6olVUYAXgAA`

	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDIzLTA2LTExVDAzOjM5OjE0WiIsCiAgImtleXMiOiB7CiAgICIyNmY4MDQ1ZWEzOTI3YTJmZmYyNGU5MDRkMjgwMWFhMTExNzY2YmJhMWU1ZjYwZTQwOTVhOGU4YmJmMmM3MmQ2IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJmZTg3Mjk3ZTEyOWQwYmU3NGEyYTdjY2Y4ZTk1N2E1NmIyYWE0ZjQ1ZWQ5NWNhNTJiNmI5ZjUxODA3MTEwNWUyIgogICAgfQogICB9LAogICAiMzJmNzM1ZGUyNTE3MTQ4NzRjMzAyM2VhMjc3M2RlNzZiMjY3NzY0OWEwYTI5Yzg1N2RlOTgzMmI0NzY5MTA3YSI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiMmJkZGVmNDgzOWJhNTdlZjBlNGY4NzA2YzIyNzM5OWVjY2E5YTk3YzZmMjI3NjA0YzI1Njk5NjgzNmMxOTkxMyIKICAgIH0KICAgfSwKICAgImEzZTRjN2FiMjgyNjRmNzk2YzA2OTc5MGE2MjljMDA0MDFkNjU2N2RmMWI3NGM3MDA5OTVmOTVkODY2MmQyYjEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogImUwYjE3MTBmMjJmMzFlNTgzN2EyYmVjNDRlYzE4ZjZmMjQzOGI0NTY3NDRmNzU5ZmE3YTRkZWI3YjRjM2JhMmEiCiAgICB9CiAgIH0sCiAgICJhYzkxYzYwODVkNjMxOGYxMTgyN2U5MmQzOGVmNTBiYzdhZDJlNGNkMDM1YjI1ODZjMDZjNTYwZTBhYWJiMjdkIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI4ZTY3Y2I1N2E4NmE0MTRjZGRlZjZiZDhmZTAwODM1NzIyOTNkY2ZmOWFlYTNlNTc4MDg4Y2MyNmEzNWNiMDgzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiYWM5MWM2MDg1ZDYzMThmMTE4MjdlOTJkMzhlZjUwYmM3YWQyZTRjZDAzNWIyNTg2YzA2YzU2MGUwYWFiYjI3ZCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICIyNmY4MDQ1ZWEzOTI3YTJmZmYyNGU5MDRkMjgwMWFhMTExNzY2YmJhMWU1ZjYwZTQwOTVhOGU4YmJmMmM3MmQ2IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiMzJmNzM1ZGUyNTE3MTQ4NzRjMzAyM2VhMjc3M2RlNzZiMjY3NzY0OWEwYTI5Yzg1N2RlOTgzMmI0NzY5MTA3YSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiYTNlNGM3YWIyODI2NGY3OTZjMDY5NzkwYTYyOWMwMDQwMWQ2NTY3ZGYxYjc0YzcwMDk5NWY5NWQ4NjYyZDJiMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiYWM5MWM2MDg1ZDYzMThmMTE4MjdlOTJkMzhlZjUwYmM3YWQyZTRjZDAzNWIyNTg2YzA2YzU2MGUwYWFiYjI3ZCIsCiAgICJzaWciOiAiZjk2MzI4OWJlZDI4OWFmMmRhMDAyMzJmOWE5ODJhZDY5MTdkYTc4ZjMwNmZjZTYwZjcxN2VmNzgwZTBhMGY1YzI1OGYzNDFiZTE3OGQ0N2UzZWEzOTUzYWFjMmJiZTgxOGUxMjJkNTAwZmIwMjJiMmU1YWRkNDNmNzY3YTU3MGMiCiAgfQogXQp9`
)

func TestCompressUncompressFS(t *testing.T) {
	files := map[string][]byte{
		"fulcio_v1.crt.pem": []byte(fulcioRootCert),
		"ctfe.pub":          []byte(ctlogPublicKey),
		"rekor.pub":         []byte(rekorPublicKey),
	}
	repo, dir, err := createRepo(context.Background(), files)
	if err != nil {
		t.Fatalf("Failed to CreateRepo: %s", err)
	}
	defer os.RemoveAll(dir)

	var buf bytes.Buffer
	fsys := os.DirFS(dir)
	if err = CompressFS(fsys, &buf, map[string]bool{"keys": true, "staged": true}); err != nil {
		t.Fatalf("Failed to compress: %v", err)
	}
	os.WriteFile("/tmp/newcompressed", buf.Bytes(), os.ModePerm)
	dstDir := t.TempDir()
	if err = Uncompress(&buf, dstDir); err != nil {
		t.Fatalf("Failed to uncompress: %v", err)
	}
	// Then check that files have been uncompressed there.
	meta, err := repo.GetMeta()
	if err != nil {
		t.Errorf("Failed to GetMeta: %s", err)
	}
	root := meta["root.json"]

	// This should have roundtripped to the new directory.
	rtRoot, err := os.ReadFile(filepath.Join(dstDir, "repository", "root.json"))
	if err != nil {
		t.Errorf("Failed to read the roundtripped root %v", err)
	}
	if !bytes.Equal(root, rtRoot) {
		t.Errorf("Roundtripped root differs:\n%s\n%s", string(root), string(rtRoot))
	}

	// As well as, say rekor.pub under targets dir
	rtRekor, err := os.ReadFile(filepath.Join(dstDir, "repository", "targets", "rekor.pub"))
	if err != nil {
		t.Errorf("Failed to read the roundtripped rekor %v", err)
	}
	if !bytes.Equal(files["rekor.pub"], rtRekor) {
		t.Errorf("Roundtripped rekor differs:\n%s\n%s", rekorPublicKey, string(rtRekor))
	}
}

func createRepo(ctx context.Context, files map[string][]byte) (tuf.LocalStore, string, error) {
	// TODO: Make this an in-memory fileystem.
	//	tmpDir := os.TempDir()
	//	dir := tmpDir + "tuf"
	dir := "/tmp/tuf"
	err := os.Mkdir(dir, os.ModePerm)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create tmp TUF dir: %w", err)
	}
	dir += "/"
	logging.FromContext(ctx).Infof("Creating the FS in %q", dir)
	local := tuf.FileSystemStore(dir, nil)

	// Create and commit a new TUF repo with the targets to the store.
	logging.FromContext(ctx).Infof("Creating new repo in %q", dir)
	r, err := tuf.NewRepoIndent(local, "", " ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to NewRepoIndent: %w", err)
	}

	// Added by vaikas
	if err := r.Init(false); err != nil {
		return nil, "", fmt.Errorf("failed to Init repo: %w", err)
	}

	// Make all metadata files expire in 6 months.
	expires := time.Now().AddDate(0, 6, 0)

	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, err := r.GenKeyWithExpires(role, expires)
		if err != nil {
			return nil, "", fmt.Errorf("failed to GenKeyWithExpires: %w", err)
		}
	}

	targets := make([]string, 0, len(files))
	for k, v := range files {
		logging.FromContext(ctx).Infof("Adding %s file", k)
		if err := writeStagedTarget(dir, k, v); err != nil {
			return nil, "", fmt.Errorf("failed to write staged target %s: %w", k, err)
		}
		targets = append(targets, k)
	}
	err = r.AddTargetsWithExpires(targets, nil, expires)
	if err != nil {
		return nil, "", fmt.Errorf("failed to add AddTargetsWithExpires: %w", err)
	}

	// Snapshot, Timestamp, and Publish the repository.
	if err := r.SnapshotWithExpires(expires); err != nil {
		return nil, "", fmt.Errorf("failed to add SnapShotWithExpires: %w", err)
	}
	if err := r.TimestampWithExpires(expires); err != nil {
		return nil, "", fmt.Errorf("failed to add TimestampWithExpires: %w", err)
	}
	if err := r.Commit(); err != nil {
		return nil, "", fmt.Errorf("failed to Commit: %w", err)
	}
	return local, dir, nil
}

func writeStagedTarget(dir, path string, data []byte) error {
	path = filepath.Join(dir, "staged", "targets", path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	return nil
}

func TestClientFromSerializedMirror(t *testing.T) {
	repo, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("failed to decode validrepository: %v", err)
	}
	root, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("failed to decode validrepository: %v", err)
	}
	tufClient, err := ClientFromSerializedMirror(context.Background(), repo, root, "targets", "/repository/")
	if err != nil {
		t.Fatalf("Failed to unserialize repo: %v", err)
	}
	targets, err := tufClient.Targets()
	if err != nil {
		t.Errorf("failed to get Targets from tuf: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}
