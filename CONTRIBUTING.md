# Contributing

Contributions are welcome when they keep sudocheck focused: fast privilege escalation auditing with actionable
remediation.

Good first contributions:

- add a remediation entry in `data/remediations.json`;
- add an expected SUID path in `data/defaults.json`;
- add scanner parser fixtures;
- add a GTFOBins-compatible database entry;
- improve SARIF or JSON output tests.

Before opening a PR:

```sh
gofmt -w main.go cmd internal data scripts
GOCACHE=/tmp/sudocheck-go-build go test ./...
go vet ./...
```

Do not add code that executes exploit commands. sudocheck explains risk; it does not exploit systems.

