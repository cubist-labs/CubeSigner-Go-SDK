.PHONY: generate-routes
generate-routes:
	@echo "Generating routes.go..."
	cd client && python3 generate_routes.py

.PHONY: fix-schema
fix-schema:
	@echo "Refactoring schema..."
	cd spec && python3 fix_schema.py

.PHONY: fix-models
fix-models:
	@echo "Running post generation script on models..."
	cd models && python3 fix_models.py

.PHONY: fmt
fmt:
	gofumpt -l -w . 
	cd spec && jq . openapi.json > temp.json && mv temp.json openapi.json

.PHONY: oapi-generate-models
oapi-generate-models:
	oapi-codegen -config tools/oapi-cfg.yml spec/openapi-refactored.json

.PHONY: generate-readme-test
generate-readme-test:
	@echo "Generating readme test..."
	cd tests && python3 generate_readme_test.py

.PHONY: generate-models
generate-models: fix-schema oapi-generate-models fix-models

.PHONY: generate-all
generate-all: generate-models generate-routes fmt
