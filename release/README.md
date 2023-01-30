# Release

This directory contain the files and scripts to run a policy-controller release.

# Cutting a Policy Controller Release

1. Release notes: Create a PR to update and review release notes in CHANGELOG.md.
  - Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.

You can get a list of pull requests since the last release by substituting in the date of the last release and running:

```
git log --pretty="* %s" --after="YYYY-MM-DD"
```

and a list of authors by running:

```
git log --pretty="* %an" --after="YYYY-MM-DD" | sort -u
```

2. Tag the repository

```shell
$ export RELEASE_TAG=<release version, eg "v1.4.0">
$ git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
$ git push origin ${RELEASE_TAG}
```

3. The tag push will start the https://github.com/sigstore/policy-controller/blob/main/.github/workflows/release.yaml job and will build and release all the artifacts and images.

4. Send an announcement email to `sigstore-dev@googlegroups.com` mailing list

5. Tweet about the new release with a fun new trigonometry pun!

6. Honk!

#### After the release:

* Add a pending new section in CHANGELOG.md to set up for the next release
