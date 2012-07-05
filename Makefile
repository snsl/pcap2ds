WIRESHARK = /Users/jchandy/src/wireshark
DATASERIES = /Users/jchandy/build/opt-macos-10.6-i386
LIBXML = /usr/include/libxml2
BOOST = /sw/include

CFLAGS = -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -I. `pkg-config --cflags glib-2.0` -I$(WIRESHARK) -W -Wall -g -I$(DATASERIES)/include -I$(LIBXML) -I$(BOOST) -DHAVE_STDARG_H
CPPFLAGS = $(CFLAGS)

TSHARK_BUILD = $(WIRESHARK)/build
TSHARK_OBJS = $(TSHARK_BUILD)/tshark-disabled_protos.o \
	$(TSHARK_BUILD)/tshark-capture_opts.o \
	$(TSHARK_BUILD)/tshark-capture_ui_utils.o \
	$(TSHARK_BUILD)/tshark-frame_data_sequence.o \
	$(TSHARK_BUILD)/tshark-packet-range.o \
	$(TSHARK_BUILD)/tshark-capture_sync.o \
	$(TSHARK_BUILD)/tshark-capture-pcap-util.o \
	$(TSHARK_BUILD)/tshark-clopts_common.o \
	$(TSHARK_BUILD)/tshark-capture_ifinfo.o \
	$(TSHARK_BUILD)/tshark-cfile.o \
	$(TSHARK_BUILD)/tshark-capture-pcap-util-unix.o \
	$(TSHARK_BUILD)/tshark-ps.o \
	$(TSHARK_BUILD)/tshark-sync_pipe_write.o \
	$(TSHARK_BUILD)/ui/libui_a-util.o

OBJS = pcap2ds.o print.o smb.o

LIBS = -L/usr/local/lib -lpcap -lwireshark -lwiretap -lcrypto -lwsutil -lz `pkg-config --libs glib-2.0` -lLintel -lDataSeries -L$(DATASERIES)/lib

all: pcap2ds

pcap2ds: config.h $(OBJS)
	rm -f dumpcap
	ln -s $(TSHARK_BUILD)/.libs/dumpcap
	g++ -o $@ $(OBJS) $(TSHARK_OBJS) $(LIBS)

config.h:
	ln -s $(TSHARK_BUILD)/config.h
	
clean:
	rm $(OBJS) pcap2ds dumpcap
