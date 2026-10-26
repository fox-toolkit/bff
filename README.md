[![Go Reference](https://pkg.go.dev/badge/github.com/fox-toolkit/bff.svg)](https://pkg.go.dev/github.com/fox-toolkit/bff)
[![tests](https://github.com/fox-toolkit/bff/actions/workflows/tests.yaml/badge.svg)](https://github.com/fox-toolkit/bff/actions?query=workflow%3Atests)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/fox-toolkit/bff)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/fox-toolkit/bff)

# BFF

BFF provides the building blocks of a Backend For Frontend for [Fox](https://github.com/fox-toolkit/fox): the OpenID
Connect login flow, a cookie session for the browser, and the tokens for the APIs behind it. The browser never sees a
token.

## Disclaimer
The current API is not yet stabilized. Breaking changes may occur before v1.0.0 and will be noted on the release note.

## Getting started
### Installation

````shell
go get -u github.com/fox-toolkit/bff
````
