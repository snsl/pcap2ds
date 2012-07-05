/* print.c
 * Routines for printing packet analysis trees.
 *
 * $Id: print.c 42053 2012-04-13 20:22:31Z darkjames $
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
#include <epan/emem.h>
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

using namespace std;

typedef struct {
	int			level;
	print_stream_t		*stream;
	gboolean		success;
	GSList		 	*src_list;
	print_dissections_e	print_dissections;
	gboolean		print_hex_for_data;
	packet_char_enc		encoding;
	epan_dissect_t		*edt;
} print_data;

typedef struct {
	int			level;
	GSList		 	*src_list;
	epan_dissect_t		*edt;
	int			tcp_num_pdus;
} write_ds_data;

GHashTable *output_only_tables = NULL;
GHashTable		*frame_times;

static void proto_tree_write_node_ds(proto_node *node, gpointer data);
static void print_escaped_xml(FILE *fh, const char *unescaped_string);

static gboolean frame_equal(gconstpointer a, gconstpointer b)
{
	if (GPOINTER_TO_UINT(a) == GPOINTER_TO_UINT(b))
		return TRUE;
	return FALSE;
}

ExtentSeries series;
OutputModule *outmodule;
DataSeriesSink *outds;
extern string smb_xml;

const ExtentType::Ptr smb_init(ExtentTypeLibrary& library, ExtentSeries& series);
void smb_finish();

extern "C"
void
write_ds_preamble(gchar *file_name)
{
	outds= new DataSeriesSink(file_name);
	ExtentTypeLibrary library;

	const ExtentType::Ptr type = smb_init(library, series);
	outmodule = new OutputModule(*outds, series, type, 128*1024);
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

#define NSTIME_TO_USECS(tp) (tp->secs * 1000000 + tp->nsecs/1000)
  
extern "C"
void proto_tree_write_ds(epan_dissect_t *edt)
{
	write_ds_data data;

	/* Create the output */
	data.level = 0;
	data.src_list = edt->pi.data_src;
	data.edt = edt;
	data.tcp_num_pdus = 0;

	outmodule->newRecord();

	proto_tree_children_foreach(edt->tree, proto_tree_write_node_ds,
	    &data);

	if (data.tcp_num_pdus == 0) {
		/* there are no frames waiting for reassembly,
		   so we can delete the frame times that we are
		   holding onto just in case its part of a packet that
		   needs to be reassembled */
		g_hash_table_remove(frame_times,
				    GUINT_TO_POINTER(edt->pi.fd->num));
	}
}

static const gchar *ignored_fields[] = {"smb.file_data"};

static const struct {
	const gchar *name;
	int   namelen;
} ignored_protos[] = 
	{{"eth", 3},
	 {"data", 4},
	 {"nbss", 4}
};

void smb_parse(field_info *fi, const string value);

/* Write out a tree's data, and any child nodes, as DataSeries */
static void
proto_tree_write_node_ds(proto_node *node, gpointer data)
{
	field_info	*fi = PNODE_FINFO(node);
	write_ds_data	*pdata = (write_ds_data*) data;
	const gchar	*label_ptr;
	char		*dfilter_string;
	size_t		chop_len;
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

		/* the first frame is at the end of the dependent_frames list */
		flist = g_slist_last(dep_frames);
		tp = (nstime_t *)g_hash_table_lookup(frame_times, flist->data);
		first_frame_time.set(NSTIME_TO_USECS(tp));
		for (flist = g_slist_nth(dep_frames, 0); flist;
		     flist = g_slist_next(flist)) {
			g_hash_table_remove(frame_times, flist->data);
		}
		pdata->tcp_num_pdus--;
		return;
	}

	if (strncmp(abbrev, "frame.", 6) == 0) {
		if (strcmp(abbrev, "frame.time_epoch") == 0) {
			/* save the frame times so that we can use it later
			   when the frame gets reassembled */
			nstime_t *tp = (nstime_t *)g_malloc(sizeof(*tp));
			tp->secs = pdata->edt->pi.fd->abs_ts.secs;
			tp->nsecs = pdata->edt->pi.fd->abs_ts.nsecs;

			first_frame_time.set(NSTIME_TO_USECS(tp));
			last_frame_time.set(NSTIME_TO_USECS(tp));

			g_hash_table_insert(frame_times,
				    GUINT_TO_POINTER(pdata->edt->pi.fd->num),
				    tp);
		}
		return;
	} else if (strncmp(abbrev, "ip.", 3) == 0) {
		if (strcmp(abbrev, "ip.src") == 0) {
			source_ip.set(1234);
		} else if (strcmp(abbrev, "ip.dst") != 0) {
			dest_ip.set(1234);
		}
		return;
	} else if (strncmp(abbrev, "tcp.", 4) == 0) {
		if (strcmp(abbrev, "tcp.data") == 0) {
			pdata->tcp_num_pdus++;
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

#if 0
	/* Text label. It's printed as a field with no name. */
	if (fi->hfinfo->id == hf_text_only) {
		/* Get the text */
		if (fi->rep) {
			label_ptr = fi->rep->representation;
		}
		else {
			label_ptr = "";
		}

		/* Show empty name since it is a required field */
		fputs("<field name=\"", pdata->fh);
		fputs("\" show=\"", pdata->fh);
		print_escaped_xml(pdata->fh, label_ptr);

		fprintf(pdata->fh, "\" size=\"%d", fi->length);

		if (node->first_child != NULL) {
			fputs("\">\n", pdata->fh);
		}
		else {
			fputs("\"/>\n", pdata->fh);
		}
	}

	/* Uninterpreted data, i.e., the "Data" protocol, is
	 * printed as a field instead of a protocol. */
	else if (fi->hfinfo->id == proto_data) {
		// XXX
		/* Write out field with data */
		//		fputs("<field name=\"data\" value=\"", pdata->fh);
		//		write_ds_field_hex_value(pdata, fi);
		//		fputs("\">\n", pdata->fh);
	}
	/* Normal protocols and fields */
	else
#endif
	  if (fi->hfinfo->type != FT_PROTOCOL || fi->hfinfo->id == proto_expert) {
		/* show, value, and unmaskedvalue attributes */
		switch (fi->hfinfo->type)
		{
		case FT_PROTOCOL:
			break;
		case FT_NONE:
			break;
		default:
			/* XXX - this is a hack until we can just call
			 * fvalue_to_string_repr() for *all* FT_* types. */
			dfilter_string = proto_construct_match_selected_string(fi,
			    pdata->edt);
			if (dfilter_string != NULL) {
				chop_len = strlen(fi->hfinfo->abbrev) + 4; /* for " == " */

				/* XXX - Remove double-quotes. Again, once we
				 * can call fvalue_to_string_repr(), we can
				 * ask it not to produce the version for
				 * display-filters, and thus, no
				 * double-quotes. */
				if (dfilter_string[strlen(dfilter_string)-1] == '"') {
					dfilter_string[strlen(dfilter_string)-1] = '\0';
					chop_len++;
				}
				smb_parse(fi, &dfilter_string[chop_len]);
			}

			/*
			 * XXX - should we omit "value" for any fields?
			 * What should we do for fields whose length is 0?
			 * They might come from a pseudo-header or from
			 * the capture header (e.g., time stamps), or
			 * they might be generated fields.
			 */
			if (fi->length > 0) {

				if (fi->hfinfo->bitmask!=0) {
				  //					fprintf(pdata->fh, "%X", fvalue_get_uinteger(&fi->value));
				}
				else {
				  //	write_pdml_field_hex_value(pdata, fi);
				}
			}
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
	smb_finish();

	outmodule->flushExtent();
	outmodule->close();
	delete outmodule;

	outds->close();
	delete outds;
}

/* Print a string, escaping out certain characters that need to
 * escaped out for XML. */
static void
print_escaped_xml(FILE *fh, const char *unescaped_string)
{
	const char *p;
	char temp_str[8];

	for (p = unescaped_string; *p != '\0'; p++) {
		switch (*p) {
			case '&':
				fputs("&amp;", fh);
				break;
			case '<':
				fputs("&lt;", fh);
				break;
			case '>':
				fputs("&gt;", fh);
				break;
			case '"':
				fputs("&quot;", fh);
				break;
			case '\'':
				fputs("&apos;", fh);
				break;
			default:
				if (g_ascii_isprint(*p))
					fputc(*p, fh);
				else {
					g_snprintf(temp_str, sizeof(temp_str), "\\x%x", (guint8)*p);
					fputs(temp_str, fh);
				}
		}
	}
}

