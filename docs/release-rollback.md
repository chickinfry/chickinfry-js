# Runtime package rollback

Each runtime package is published once per release tag. For a routine rollback,
retire the bad release using the registry's supported action and publish a higher
version.

| Registry | Reversible action | Irreversible limit | Who runs it |
| --- | --- | --- | --- |
| npm | `npm deprecate <pkg>@<version> "<reason>"` marks the version as deprecated. The tarball stays downloadable. | Unpublishing is irreversible and the removed version cannot be reused. | For routine rollback, the release owner runs `npm deprecate`, then publishes the fixed version. |
| PyPI | `yank` removes the version from the default resolver view while the file stays reachable by exact pin | A filename cannot be reused once uploaded, even after yank | Release owner yanks on the PyPI project page, then publishes the fixed version |
| pub.dev | `retract` hides the version from resolution; the archive stays stored | A retracted version cannot be republished with the same version string | Release owner runs `dart pub publish` for the fixed version, then retracts the bad one |
| Maven Central | Nothing can be deleted or retracted after the release is closed | A bad artifact stays resolvable forever, so the only fix is to publish a higher version and stop documenting the old one | Release owner publishes the fixed version; the bad version stays in the repository |
| GitHub mirror tag (Go, Rust, Swift) | Delete the tag and re-tag the corrected commit, then let the mirror sync run | A module proxy caches a resolved version, so a moved tag is not observed by clients that already resolved it | Release owner deletes the tag; the mirror sync workflow republishes from the corrected commit |

## Order

1. Retire the bad version in its registry with the action above.
2. Publish the fixed version from a new release tag. The publish workflow only runs on `v*` tags that match the package version.
3. Update the release receipt in the CLI repository to the fixed version, so the language gate reopens on a version that the registry actually serves.
4. Post the reason and the registry link in the tracking issue.

## npm 0.5.0 cutover

For a package older than 72 hours, npm permits unpublishing when no public
registry packages depend on it, it had fewer than 300 downloads in the last week,
and it has one owner or maintainer. See the [npm unpublish policy](https://docs.npmjs.com/policies/unpublish/).

1. Confirm that CI uses the verified runtime tarball and that the npm package
   meets the unpublish conditions.
2. The package owner unpublishes the old versions using two-factor authentication
   and records the time of the last removal.
3. After removing every version, wait at least 24 hours from the last removal.
   Then request the `release-tag.yml` run on the approved `main` commit to
   publish 0.5.0.

For routine rollbacks, a yank or deprecation keeps the artifact reachable for
existing pins. Maven Central publishes the replacement at a higher version.

