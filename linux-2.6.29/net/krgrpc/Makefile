#
# Makefile for the Kerrighed Remote Procedure Call layer
#

obj-$(CONFIG_KRGRPC) := krgrpc.o

krgrpc-y := rpc.o comlayer.o thread_pool.o rpclayer.o monitor.o rpc_hotplug.o synchro.o

EXTRA_CFLAGS += -I$(M) -Wall -Werror

# end of file
