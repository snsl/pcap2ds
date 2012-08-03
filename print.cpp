/* print.c
 *
 * Routines for converting pcap files to DataSeries files
 *
 * Copyright (C) 2012 University of Connecticut. All rights reserved.
 *
 * Heavily borrowed from Wireshark/print.c (Id: 42053 2012-04-13 20:22:31Z darkjames $
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

extern "C" {
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/tvbuff.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#include "packet-range.h"
#include "print.h"
//#include "isprint.h"
#include "ps.h"
#include "version_info.h"
#include <wsutil/file_util.h>
#include <epan/charsets.h>
#include <epan/dissectors/packet-data.h>
#include <epan/dissectors/packet-frame.h>
#include <epan/filesystem.h>
#include <cfile.h>
}

#include <DataSeries/DataSeriesModule.hpp>

#include <protocol.hpp>
#include <smb.hpp>
#include <nfs.hpp>
#include <iscsi.hpp>

using namespace std;

// Currently this packet_type variable is being set here, but eventually the idea would be to move this
//   to a user provided variable
extern "C" gchar * dissect_type;
string packet_type;
// string packet_type = (string) dissect_type;
// Creation of smb, nfs & iscsi instances | SEE IF THERE IS A BETTER WAY
smb smb; nfs nfs; iscsi iscsi;

typedef struct {
	int			level;
	epan_dissect_t		*edt;
	int			tcp_num_fragments;
} write_ds_data;

GHashTable *output_only_tables = NULL;
GHashTable		*frame_times;

static void proto_tree_write_node_ds(proto_node *node, gpointer data);

static gboolean frame_equal(gconstpointer a, gconstpointer b)
{
	if (GPOINTER_TO_UINT(a) == GPOINTER_TO_UINT(b))
		return TRUE;
	return FALSE;
}

ExtentSeries series;
OutputModule *outmodule;
DataSeriesSink *outds;

//const ExtentType::Ptr dissect_init(ExtentTypeLibrary& library, ExtentSeries& series, string packet_type);
//void dissect_finish(string packet_type);

extern "C"
void
write_ds_preamble(gchar *file_name)	// ~!~ NEED(?) CHANGE HERE!! ~!~
{
	outds= new DataSeriesSink(file_name);
	ExtentTypeLibrary library;

	//Note Bene: Very VERY strange that this current setup seems to work with make...
	ExtentType::Ptr type; // Problem here causes crash, figure out why...
	packet_type = (string) dissect_type;

	// Check as to what type of dissection is going to be done
	if(packet_type == "smb")
		type = smb.init(library, series);	// ~!~ CHANGE HERE!! ~!~
	else if(packet_type == "nfs")
		type = nfs.init(library, series);
	else if(packet_type == "iscsi")
		type = iscsi.init(library, series);

	//Note Bene: The type casting going on here might not work... Ensure crash does not happen
	outmodule = new OutputModule(*outds, series, (const ExtentType::Ptr) type, 128*1024);
	outds->writeExtentLibrary(library);

	frame_times = g_hash_table_new_full(g_direct_hash, frame_equal,
					    NULL, g_free);
}

Int64Field first_frame_time(series, "first_frame_time");
Int64Field last_frame_time(series, "last_frame_time");
Int32Field source_ip(series, "source_ip");
Int32Field source_port(series, "source_port");
Int32Field dest_ip(series, "dest_ip");
Int32Field dest_port(series, "dest_port");

#define NSTIME_TO_USECS(tp) ((int64_t)tp->secs * 1000000 + tp->nsecs/1000)

//void dissect_packet_start(ExtentType::Ptr type);
//void dissect_parse(field_info *fi, string packet_type);

extern "C"
void proto_tree_write_ds(epan_dissect_t *edt)
{
	write_ds_data data;

	/* there is no easy way to find out if this packet is a
	   segment of a yet to be reassembled TCP PDU.  For now, we'll
	   find the TCP proto node, and if it has a tcp.data node,
	   then we'll assume that it is a TCP segment in a
	   multisegment PDU.  If it is, we'll ignore it as long its
	   not the last segment in the PDU
	*/

	proto_node *tcp = (proto_node *)edt->pi.tcp_tree;
	if (tcp) {
		proto_node *node;
		gboolean found_tcp_data = false;
		for (node = tcp->first_child; node; node = node->next) {
			header_field_info *hfinfo = node->finfo->hfinfo;
			if (strcmp(hfinfo->abbrev, "tcp.data") == 0) {
				/* We need to set the first_frame_time */
				nstime_t *tp;
				tp = (nstime_t *)g_malloc(sizeof(*tp));
				tp->secs = edt->pi.fd->abs_ts.secs;
				tp->nsecs = edt->pi.fd->abs_ts.nsecs;

				/* save the frame time so that we can
				   use it later when the frame gets
				   reassembled into a TCP PDU */
				g_hash_table_insert(frame_times,
						    GUINT_TO_POINTER(edt->pi.fd->num),
						    tp);
				/* there may be multiple tcp.data fragments
				   in this packet, so don't return yet */
				found_tcp_data = true;
			}
		}

		/* if we found tcp.data and there is no dependent_frames list,
		   then this frame is not the last segment in the PDU, and has
		   not been reassembled.  So, just ignore the packet.
		*/
		if (found_tcp_data == true && edt->pi.dependent_frames == NULL) {
			return;
		}
	}
	
	/* Create the output */
	data.level = 0;
	data.edt = edt;
	data.tcp_num_fragments = 0;

	outmodule->newRecord();

	if(packet_type =="smb")	// ~!~ CHANGE HERE!! ~!~
		smb.packet_start(outmodule->getOutputType());
	else if(packet_type == "nfs")
		nfs.packet_start(outmodule->getOutputType());
	else if(packet_type == "iscsi")
		iscsi.packet_start(outmodule->getOutputType());

	proto_tree_children_foreach(edt->tree, proto_tree_write_node_ds, &data);

	if (data.tcp_num_fragments == 0) {
		/* there are no frames waiting for reassembly,
		   so we can delete the frame times that we are
		   holding onto just in case its part of a packet that
		   needs to be reassembled */
		g_hash_table_remove(frame_times,
				    GUINT_TO_POINTER(edt->pi.fd->num));
	}
}

static const gchar *ignored_fields[] = {" "};  //smb.file_data"};	// Possibly switch to being nfs? || Does not seem that nfs.file_data exists
// It appears that this above line is called later on in the code, need to go through later and see if this line can be removed/switch-statemented to only occur for smb

static const struct {
	const gchar *name;
	int   namelen;
} ignored_protos[] = 
	{{"eth", 3},
	 {"data", 4},
	 {"nbss", 4}
};

/* Write out a tree's data, and any child nodes, as DataSeries */
static void
proto_tree_write_node_ds(proto_node *node, gpointer data)	// ~!~ MAY NEED TO ADD PACKET_TYPE TO THIS ~!~
{
	field_info	*fi = PNODE_FINFO(node);
	write_ds_data	*pdata = (write_ds_data*) data;
	int		i;
	gboolean wrap_in_fake_protocol;
	const gchar	*abbrev = fi->hfinfo->abbrev;

	g_assert(fi && "dissection with an invisible proto tree?");

	wrap_in_fake_protocol =
	    ((fi->hfinfo->type != FT_PROTOCOL) && (pdata->level == 0));

	if (wrap_in_fake_protocol) {
		GSList *flist;
		GSList *dep_frames = pdata->edt->pi.dependent_frames;
		nstime_t *tp;

		/* this frame is the last segment of a larger TCP PDU */
		/* find the first frame at end of the dependent_frames list */
		/* and set the first_frame_time */
		flist = g_slist_last(dep_frames);
		tp = (nstime_t *)g_hash_table_lookup(frame_times, flist->data);
		first_frame_time.set(NSTIME_TO_USECS(tp));

		/* remove the frame times for all the frams in this segment */
		for (flist = g_slist_nth(dep_frames, 0); flist;
		     flist = g_slist_next(flist)) {
			g_hash_table_remove(frame_times, flist->data);
		}
		pdata->tcp_num_fragments--;
		return;
	}

	if (strncmp(abbrev, "frame.", 6) == 0) {
		if (strcmp(abbrev, "frame.time_epoch") == 0) {
			nstime_t *tp = (nstime_t *)g_malloc(sizeof(*tp));
			tp->secs = pdata->edt->pi.fd->abs_ts.secs;
			tp->nsecs = pdata->edt->pi.fd->abs_ts.nsecs;

			first_frame_time.set(NSTIME_TO_USECS(tp));
			last_frame_time.set(NSTIME_TO_USECS(tp));
		}
		return;
	} else if (strncmp(abbrev, "ip.", 3) == 0) {
		if (strcmp(abbrev, "ip.src") == 0) {
			source_ip.set(fi->value.value.sinteger);
		} else if (strcmp(abbrev, "ip.dst") == 0) {
			dest_ip.set(fi->value.value.sinteger);
		}
		return;
	} else if (strncmp(abbrev, "tcp.", 4) == 0) {
		if (strcmp(abbrev, "tcp.data") == 0) {
			pdata->tcp_num_fragments++;
		} else if (strcmp(abbrev, "tcp.srcport") == 0) {
			source_port.set(fi->value.value.sinteger);
		} else if (strcmp(abbrev, "tcp.dstport") == 0) {
			dest_port.set(fi->value.value.sinteger);
		}
		return;
	} else {

		for (i=0;
		     i<(int)(sizeof(ignored_protos)/sizeof(*ignored_protos));
		     i++) {
			int namelen = ignored_protos[i].namelen;
			if (strncmp(abbrev,ignored_protos[i].name,namelen)==0) {
				if (abbrev[namelen] == '.' ||
				    abbrev[namelen] == 0) {
					return;
				}
			}
		}
	}

	for (i=0; i<(int)(sizeof(ignored_fields)/sizeof(*ignored_fields)); i++) {
		if (strcmp(abbrev, ignored_fields[i]) == 0)
			return;
	}

	/* Text label. */
	if (fi->hfinfo->id == hf_text_only) {
		// we can usually ignore these nodes but sometimes, it
		// would be useful to grab information from these
		// nodes rather than recurse further into the
		// sub-nodes.  For example, the top-level smb.flags is
		// a hf_text_only node.  If we print out the flags
		// here, we don't have to have separate DS columns for
		// each flag.XXX type.  Unfortunately, there doesn't
		// seem to be a way to find out the name of the text
		// node (e.g. "smb.flags") and thus avoid going down
		// the tree.
	}

	/* Uninterpreted data, i.e., the "Data" protocol */
	else if (fi->hfinfo->id == proto_data) {
		// we can usually ignore these data nodes
	}
	/* Normal protocols and fields */
	else
	  if (fi->hfinfo->type != FT_PROTOCOL || fi->hfinfo->id == proto_expert) {
		/* show, value, and unmaskedvalue attributes */
		switch (fi->hfinfo->type)
		{
		case FT_PROTOCOL:
			break;
		case FT_NONE:
			break;
		default:
			if(packet_type == "smb")	// ~!~ CHANGE HERE!! ~!~
				smb.parse(fi);
			else if(packet_type == "nfs")
				nfs.parse(fi);
			else if(packet_type == "iscsi")
				iscsi.parse(fi);
		}
	}

	/* We always print all levels for PDML. Recurse here. */
	if (node->first_child != NULL) {
		pdata->level++;
		proto_tree_children_foreach(node,
				proto_tree_write_node_ds, pdata);
		pdata->level--;
	}

	/* Take back the extra level we added for fake wrapper protocol */
	if (wrap_in_fake_protocol) {
		pdata->level--;
	}

}

extern "C"
void
write_ds_finale()
{
	if(packet_type == "smb")	// ~!~ CHANGE HERE ~!~
		smb.finish();
	else if(packet_type == "nfs")
		nfs.finish();
	else if(packet_type == "iscsi")
		iscsi.finish();

	outmodule->flushExtent();
	outmodule->close();
	delete outmodule;

	outds->close();
	delete outds;
}
