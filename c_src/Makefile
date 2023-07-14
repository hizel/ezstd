
PROJECT_NIF_NAME=ezstd_nif

include nif.mk

ifeq ($(UNAME_SYS), darwin)
	LDFLAGS +=  -Wl,-U,_enif_inspect_binary \
				-Wl,-U,_enif_get_uint \
				-Wl,-U,_enif_make_atom \
				-Wl,-U,_enif_make_existing_atom \
				-Wl,-U,_enif_make_new_binary \
				-Wl,-U,_enif_make_tuple \
                                -Wl,-U,_enif_alloc_resource \
                                -Wl,-U,_enif_make_resource \
                                -Wl,-U,_enif_open_resource_type \
                                -Wl,-U,_enif_release_resource \
                                -Wl,-U,_enif_get_resource \
                                -Wl,-U,_enif_make_uint

endif
#-DNDEBUG
CFLAGS += -O0 \
			-I$(BASEDIR)/_build/deps/zstd/lib \
			-g -ggdb -Wextra -Werror -Wno-missing-field-initializers

LDFLAGS  += -L$(BASEDIR)/_build/deps/zstd/lib \
			-lzstd			
