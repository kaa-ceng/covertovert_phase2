# Makefile
# Do not edit the Makefile!

JSON_FILE=config.json

send:
	@echo "Sender is running!"
	@python3 run.py send
	@echo "Sender is finished!"

receive:
	@echo "Receiver is running!"
	@python3 run.py receive
	@echo "Receiver is finished!"

compare:
	@sentLog=$$(jq -r '.send.parameters.log_file_name' $(JSON_FILE)); \
	receivedLog=$$(jq -r '.receive.parameters.log_file_name' $(JSON_FILE)); \
	echo "Sender Log File: $$sentLog"; \
	echo "Receiver Log File: $$receivedLog"; \
	if [ ! -f "$$sentLog" ]; then \
	    echo "$$sentLog file does not exist!"; \
	    exit 1; \
	fi; \
	if [ ! -f "$$receivedLog" ]; then \
	    echo "$$receivedLog does not exist!"; \
	    exit 1; \
	fi; \
	if cmp --silent "$$sentLog" "$$receivedLog"; then \
	    echo "Done: Files are identical!"; \
	else \
	    echo "Fail: Files are different!"; \
	    diff "$$sentLog" "$$receivedLog" || true; \
	fi

documentation:
	@echo "Documentation is creating with sphinx!"
	@cd docs && make html
	@echo "Documentation is finished, check the docs/_build/html!"
