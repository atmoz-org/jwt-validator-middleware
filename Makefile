.PHONY: test coverage clean

# Run all tests
test:
	go test -v ./...

# Run tests with coverage (outputs coverage.out, prints summary)
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Run tests with coverage and open HTML report in default browser
coverage-html: coverage
	go tool cover -html=coverage.out -o coverage.html
	@command -v open >/dev/null 2>&1 && open coverage.html || xdg-open coverage.html 2>/dev/null || true

# Remove coverage artifacts
clean:
	rm -f coverage.out coverage.html
