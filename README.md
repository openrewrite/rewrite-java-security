![Logo](https://github.com/openrewrite/rewrite/raw/main/doc/logo-oss.png)
### Patch Java security vulnerabilities. Automatically.

[![ci](https://github.com/openrewrite/rewrite-java-security/actions/workflows/ci.yml/badge.svg)](https://github.com/openrewrite/rewrite-java-security/actions/workflows/ci.yml)
[![Apache 2.0](https://img.shields.io/github/license/openrewrite/rewrite-java-security.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/org.openrewrite.recipe/rewrite-java-security.svg)](https://mvnrepository.com/artifact/org.openrewrite.recipe/rewrite-java-security)
[![Revved up by Develocity](https://img.shields.io/badge/Revved%20up%20by-Develocity-06A0CE?logo=Gradle&labelColor=02303A)](https://ge.openrewrite.org/scans)

### What is this?

This project implements a [Rewrite module](https://github.com/openrewrite/rewrite) that patches common Java security vulnerabilities.

Browse [a selection of recipes available through this module in the recipe catalog](https://docs.openrewrite.org/recipes/java/security).

## Contributing

We appreciate all types of contributions. See the [contributing guide](https://github.com/openrewrite/.github/blob/main/CONTRIBUTING.md) for detailed instructions on how to get started.

## Why is this archived?

There has not been much activity on this repository in the last year, owing in large part to the fact that many recipes are built on an original concept of data flow analysis (DFA) in rewrite-analysis that is gradually being phased out in favor of DFA built on top of the [Traits API](https://github.com/openrewrite/rewrite/tree/main/rewrite-core/src/main/java/org/openrewrite/trait).

We are leaving this repository here in "public archive" state for historical reasons and so that code that corresponds to binary artifacts of rewrite-java-security in Maven Central is easy to refer to.

Going forward, Moderne will be staffing full time security research to develop security recipes, initially and perhaps always in proprietary form. Others are welcome to develop security recipes either in a proprietary form or in OSS according to their preference.
