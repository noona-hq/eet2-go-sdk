COVERAGE_PROFILE ?= coverage.out
COVERAGE_HTML    ?= coverage.html

.PHONY: test
test:
	go test -race ./...

.PHONY: ci-test
ci-test:
	gotestsum --junitfile unit-tests.xml -- -race -count=1 ./...

.PHONY: test-coverage
test-coverage:
	gotestsum -- -count=1 -covermode=atomic -coverprofile=$(COVERAGE_PROFILE) ./...
	go tool cover -func=$(COVERAGE_PROFILE) | tail -1
	go tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)

.PHONY: test-playground
test-playground:
	go test -race -tags playground -run TestPlayground -count=1 -v .

.PHONY: lint
lint:
	test -z "$$(gofmt -l .)"
	test -z "$$(go fix -diff ./...)"
	test -z "$$(go fix -tags playground -diff ./...)"
	go vet ./...
	go vet -tags playground ./...
	go mod tidy -diff

.PHONY: vulncheck
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
