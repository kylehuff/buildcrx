CC = gcc
ifeq ($(CC),gcc)
	LBITS := $(shell getconf LONG_BIT)
	ifeq ($(LBITS),64)
		DISTDIR=linux_x86_64-gcc3
	else
		DISTDIR=linux_x86-gcc3
	endif
	EXT=
else
	DISTDIR=winnt_x86-msvc
	EXT=.exe
endif
OUTDIR=bin
LIBDIR=libs/openssl/${DISTDIR}
INCLUDE=include/openssl
CFLAGS = -L ${LIBDIR} -I ${INCLUDE} -g -Wall
ifeq ($(CC),gcc)
	LDFLAGS = -lm -DDEBUG -lcrypto -ldl
else
	LDFLAGS = -lm -DDEBUG -lcrypto -lgdi32
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
