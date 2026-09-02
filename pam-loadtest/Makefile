.PHONY: test build release browser-install verify recon report deploy-test

test:
	go test ./...
	npm test --prefix browser-worker
	cd recon && npm test

build:
	go build -o bin/pam-loadtest ./cmd/pam-loadtest

release:
	bash deploy/agent/build.sh

deploy-test:
	bash deploy/agent/tests/deploy_test.sh

browser-install:
	npm ci --prefix browser-worker
	npx --prefix browser-worker playwright install chromium

verify: test
	go vet ./...
	go build ./cmd/pam-loadtest

recon:
	cd recon && npm run capture -- --config config.json

report:
	cd recon && npm run report
