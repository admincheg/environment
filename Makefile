FILES = \
	e

ifeq ($(PREFIX),)
	PREFIX="${HOME}/.bin"
endif

default:
	@ echo "You can specify PREFIX environment variable before installing"
	@ echo "By default we place libraries to $(PREFIX)"
	@ echo "Installation command is 'make install'"

install:
	@ for i in $(FILES); do \
		install -D -m 0644 "$${i}" "$(PREFIX)/$${i}" ; \
	done

	@ echo "Environment binary installed to $(PREFIX)"
	@ echo ""
	@ echo "Be careful, for using it your PATH environment variable should"
	@ echo "contains $(PREFIX) directory."

