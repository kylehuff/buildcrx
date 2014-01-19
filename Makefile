ifneq (,$(findstring mingw,$(CC)))
	OS = Windows_NT
endif

ifeq ($(OS),Windows_NT)
	DISTDIR=winnt_x86-msvc
	EXT=.exe
else
	LBITS := $(shell getconf LONG_BIT)
	ifeq ($(LBITS),64)
		DISTDIR=linux_x86_64-gcc3
	else
		DISTDIR=linux_x86-gcc3
	endif
	EXT=
endif

OUTDIR=bin
LIBDIR=libs/openssl/${DISTDIR}
INCLUDE=include/openssl
CFLAGS = -L ${LIBDIR} -I ${INCLUDE} -g -Wall

ifeq ($(OS),Windows_NT)
	LDFLAGS = -lm -DDEBUG -lcrypto -lgdi32
else
	LDFLAGS = -lm -DDEBUG -lcrypto -ldl
endif


buildcrx : buildcrx.c
	@set -e; if [ ! -d "${OUTDIR}/${DISTDIR}" ]; then \
		mkdir -vp ${OUTDIR}/${DISTDIR}; \
	fi
	$(CC) $(CFLAGS) -o ${OUTDIR}/${DISTDIR}/buildcrx${EXT} buildcrx.c $(LDFLAGS)

clean:
	@set -e; echo "cleaning output directories...";
	@set -e; for d in $(OUTDIR)/*; do \
		for f in $$d/*; do \
			if [ -e "$$f" ]; then \
				rm -v $$f; \
			fi; \
		done; \
	done
	@set -e; echo "done.";
