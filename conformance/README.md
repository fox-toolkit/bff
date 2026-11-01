# Conformance

This module runs the client test plans of the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against the BFF.

Start the suite. The first start takes about a minute.

```bash
docker compose -f conformance/compose.yaml up -d
```

Run the plans from the `conformance` directory. Set `RP_REDIS_ADDR` to also run the plans with the sessions stored in
Redis.

```bash
RP_CONFORMANCE_SUITE=https://localhost.emobix.co.uk:8443 RP_REDIS_ADDR=localhost:6379 go test -v -timeout 30m ./...
```

Run one plan, setup or module with `-run`.

```bash
RP_CONFORMANCE_SUITE=https://localhost.emobix.co.uk:8443 go test -v -run 'TestConformance/fapi2/^memory$' ./...
```

Run `go work use ./conformance` at the root of the repository to add this module to an existing `go.work`.

The logs of each module are in `results/<plan>/<setup>/<module>/`. A module that does not pass is listed in the
`expected` field of its plan file, with the reason.

Stop the suite.

```bash
docker compose -f conformance/compose.yaml down -v
```
