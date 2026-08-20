BINARY_NAME=scando
CMD_DIR=./cmd/scando
INSTALL_DIR=/usr/local/bin

.PHONY: all build install uninstall clean check test

all: build

build:
	go build -ldflags="-s -w" -o $(BINARY_NAME) $(CMD_DIR)

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@sudo cp $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo chmod 755 $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "$(BINARY_NAME) installed successfully!"

uninstall:
	@echo "Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)

clean:
	@rm -f $(BINARY_NAME)

check:
	./$(BINARY_NAME) -check

test:
	go test -v ./...
