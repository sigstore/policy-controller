#!/usr/bin/env bash
#
# Copyright 2022 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# This script will iterate over expected failures for invalid CIPs in
# ./test/testdata/policy-controller/invalid
# Each of the CIP specifies a line that looks like this:
# ERROR:expected error goes here
# And for each invalid CIP, the error is validated to be the expected failure.
# You can have multiple ERROR lines and then each one will be matched.
# Note that we grep with the exact match so as not to get bamboozled by the
# grep regexp rules. This allows us to match fields in arrays (like
# authorities[0].keyless.identities) for example.

# We the iterate over expected successes but with failures for "warn" CIPs in
# ./test/testdata/policy-controller/warn
# Each of the CIP specifies a line that looks like this:
# Warning: missing field(s): spec.authorities[0].keyless.identities
# And for each "warn" CIP, the warning is validated and we make sure the
# CIP is still admitted and therefore it's only a warning.
# Note that we grep with the exact match so as not to get bamboozled by the
# grep regexp rules. This allows us to match fields in arrays (like
# authorities[0].keyless.identities) for example.

# Finally we loop over good CIPs in
# ./test/testdata/policy-controller/valid
# Each of the CIP is expected to succeed and we error out if it fails to be
# created.

# We only want to loop over error / warning lines, not words.
IFS=$'\n'
echo '::group:: Invalid policy tests:'
for i in `ls ./test/testdata/policy-controller/invalid/`
do
  echo Testing: $i
  # Grab the expected error from the CIP
  expected_errors=$(grep ERROR: test/testdata/policy-controller/invalid/${i} | cut -d ':' -f 2-)
  err_file="./kubectl_err"
  if kubectl create -f ./test/testdata/policy-controller/invalid/$i 2> ${err_file}; then
    echo "${i} policy created when it should not have"
    exit 1
  else
    for expected_error in ${expected_errors}
    do
      echo looking for error: ${expected_error}
      if ! grep --fixed-strings -q "${expected_error}" ${err_file} ; then
        echo Did not get expected failure message, wanted "${expected_error}", got
        cat ${err_file}
        exit 1
      else
        echo "${i} rejected as expected"
      fi
    done
  fi
done
echo '::endgroup:: Invalid policy test:'

echo '::group:: Warning policy tests:'
for i in `ls ./test/testdata/policy-controller/warn/`
do
  echo Testing: $i
  # Grab the expected error from the CIP
  expected_warnings=$(grep Warning: test/testdata/policy-controller/warn/${i} | cut -d ' ' -f 2-)
  warn_file="./kubectl_warn"
  if ! kubectl create -f ./test/testdata/policy-controller/warn/$i 2> ${warn_file}; then
    echo "${i} policy rejected when it should have only warned"
    cat ${warn_file}
    exit 1
  else
    for expected_warning in ${expected_warnings}
    do
      echo looking for warning: ${expected_warning}
      if ! grep --fixed-strings -q "${expected_warning}" ${warn_file} ; then
        echo Did not get expected warning message, wanted "${expected_warning}", got
        cat ${warn_file}
        exit 1
      else
        echo "${i} created and warning found as expected"
      fi
    done
  fi
  kubectl delete -f ./test/testdata/policy-controller/warn/$i --ignore-not-found=true
done
echo '::endgroup:: Warning policy test:'

echo '::group:: Valid policy test:'
for i in `ls ./test/testdata/policy-controller/valid/`
do
  if kubectl create -f ./test/testdata/policy-controller/valid/$i ; then
    echo "${i} created as expected"
  else
    echo "${i} failed when it should not have"
    exit 1
  fi

  kubectl delete -f ./test/testdata/policy-controller/valid/$i --ignore-not-found=true
done

echo '::endgroup:: Valid policy test:'
