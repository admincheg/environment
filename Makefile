FILES = \
	e

ifeq ($(PREFIX),)
	PREFIX="${HOME}/.bin"
endif

ifeq ($(OWLLIB_PATH),)
	OWLLIB_PATH="${HOME}/.local/share/owllib"
endif

default:
	@ echo "You can specify PREFIX environment variable before installing"
	@ echo "By default we place libraries to $(PREFIX)"
	@ echo "Installation command is 'make install'"

install:
	@ if [[ ! -f "$(OWLLIB_PATH)/helpers.sh" ]]; then \
		echo "Owllib is not found in $(OWLLIB_PATH)"; \
		echo "You can spectify OWLLIB_PATH environment variable"; \
		echo "Or you can obtain it from https://github.com/admincheg/owllib"; \
		exit 1; \
	fi
	@ for i in $(FILES); do \
		install -D -m 0644 "$${i}" "$(PREFIX)/$${i}" ; \
	done

	@ echo "Environment binary installed to $(PREFIX)"
	@ echo ""
	@ echo "Be careful, for using it your PATH environment variable should"
	@ echo "contains $(PREFIX) directory."

