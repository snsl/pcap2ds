/* print.c
 *
 * Routines for converting SMB pcap files to DataSeries files
 *
 * Copyright (C) 2012 University of Connecticut. All rights reserved.
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

#include <string>
#include <set>
#include <tr1/unordered_map>

#include <DataSeries/DataSeriesModule.hpp>
extern "C" {
#include "config.h"
#include <epan/proto.h>
}


using namespace std;

typedef struct {
	ExtentType::fieldType type;
	Field *field;
	bool nullable;
} ExtentTypeFieldInfo;

typedef tr1::unordered_map<string,ExtentTypeFieldInfo> FieldMap;
static FieldMap epan2dstype;
static set<string> ignored_fields;
static set<string> special_case_fields;

static
void add_proto_fields(const gchar *proto_name, int proto_name_strip_len,
		      FieldMap &map,
		      ExtentSeries& series,
		      ExtentType::Ptr type,
		      bool (*exception_handler)(const gchar*,
						const header_field_info*,
						ExtentSeries &series,
						FieldMap &map))
{
	int proto_id = proto_get_id_by_filter_name(proto_name);
	void *cookie;
	header_field_info *hfinfo;

	for (hfinfo = proto_get_first_protocol_field(proto_id, &cookie);
	     hfinfo;
	     hfinfo = proto_get_next_protocol_field(&cookie)) {

		const gchar *epanFieldName = hfinfo->abbrev;
		const gchar *extentFieldName =epanFieldName+proto_name_strip_len;

		Field *field;

		if (!type->hasColumn(extentFieldName)) {
			fprintf(stderr, "Field %s does not exist in NFS XML ExtentType Description\n", extentFieldName);
			continue;
		}

		if (exception_handler != NULL &&
		    exception_handler(extentFieldName, hfinfo, series, map))
			continue;

		int flags = 0;
		if (type->getNullable(extentFieldName))
			flags = Field::flag_nullable;

		ExtentType::fieldType ft = type->getFieldType(extentFieldName);

		switch(ft) {
		case ExtentType::ft_bool:
			field = new BoolField(series, extentFieldName, flags);
			assert(hfinfo->type == FT_BOOLEAN);
			break;
		case ExtentType::ft_byte:
			field = new ByteField(series, extentFieldName, flags);
			assert(hfinfo->type == FT_UINT8);
			break;

		case ExtentType::ft_int32:
			field = new Int32Field(series, extentFieldName, flags);
			assert(hfinfo->type == FT_UINT16 ||
			       hfinfo->type == FT_FRAMENUM ||
			       hfinfo->type == FT_UINT32);
			break;

		case ExtentType::ft_int64:
			assert(hfinfo->type == FT_UINT64 ||
			       hfinfo->type == FT_BYTES ||
			       hfinfo->type == FT_ABSOLUTE_TIME ||
			       hfinfo->type == FT_RELATIVE_TIME);
			field = new Int64Field(series, extentFieldName, flags);
			break;

		case ExtentType::ft_double:
			field = new DoubleField(series, extentFieldName, flags);
			break;

		case ExtentType::ft_variable32:
			field = new Variable32Field(series, extentFieldName,
						    flags);
			break;

		case ExtentType::ft_fixedwidth:
			field = new FixedWidthField(series, extentFieldName,
						    flags);
			assert(hfinfo->type == FT_GUID);
			break;

		default:
			assert(0);
			break;
		}

		ExtentTypeFieldInfo &etfi = map[epanFieldName];
		etfi.field = field;
		etfi.type = ft;
		etfi.nullable = (flags == Field::flag_nullable);
	}
}

static Int32Field *recommended_attr_field;
static Int32Field *reply_status_field;

static bool handle_nfs_exception(const gchar *extentName,
				 const header_field_info *hfinfo,
				 ExtentSeries &series,
				 FieldMap &map)
{
	if (strcmp(extentName,"attr") == 0) {
		if (strcmp(hfinfo->name, "recc_attr")) {
			recommended_attr_field =
				new Int32Field(series, "recc_attr",
					       Field::flag_nullable);
			return true;
		}
	} else if (strcmp(extentName,"status") == 0) {
		if (strcmp(hfinfo->name, "Status")) {
			reply_status_field =
				new Int32Field(series, "reply_status",
					       Field::flag_nullable);
			return true;
		}
	}

	return false;
}

const ExtentType::Ptr
nfs_init(ExtentTypeLibrary& library, ExtentSeries& series)
{
	const ExtentType::Ptr type = library.registerTypePtr(nfs_xml);
	series.setType(type);

	add_proto_fields("nfs", 4, epan2dstype, series, type, handle_nfs_exception);	// Note: getting rid of shortening of field so that one can see what is an nfs.* property
	add_proto_fields("rpc", 0, epan2dstype, series, type, NULL);
//	add_proto_fields("smb2", 0, epan2dstype, series, type, NULL);

	ignored_fields.insert("rpc.auth.gid");
	ignored_fields.insert("rpc.auth.uid");
	ignored_fields.insert("rpc.auth.length");
	ignored_fields.insert("rpc.auth.stamp");
	ignored_fields.insert("rpc.auth.machinename");
	ignored_fields.insert("rpc.auth.flavor");
	ignored_fields.insert("rpc.programversion");
	ignored_fields.insert("rpc.lastfrag");
	ignored_fields.insert("rpc.xid");
	ignored_fields.insert("rpc.fraglen");
	ignored_fields.insert("rpc.msgtyp");
	ignored_fields.insert("rpc.version");
	ignored_fields.insert("rpc.program");
	ignored_fields.insert("rpc.procedure");
	ignored_fields.insert("rpc.replystat");
	ignored_fields.insert("rpc.repframe");
	ignored_fields.insert("rpc.time");
	ignored_fields.insert("rpc.state_accept");
	ignored_fields.insert("rpc.value_follows");
	ignored_fields.insert("rpc.call.dup");
	ignored_fields.insert("udp.port");
	ignored_fields.insert("udp.length");
	ignored_fields.insert("udp.checksum_coverage");
	ignored_fields.insert("udp.checksum");
	ignored_fields.insert("udp.checksum_good");
	ignored_fields.insert("udp.checksum_bad");
	ignored_fields.insert("udp.srcport");
	ignored_fields.insert("udp.dstport");
	ignored_fields.insert("portmap.procedure_v2");
	ignored_fields.insert("portmap.prog");
	ignored_fields.insert("portmap.version");
	ignored_fields.insert("portmap.proto");
	ignored_fields.insert("portmap.port");

	return type;
}

void nfs_finish()
{
	FieldMap::iterator i;
	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
		ExtentTypeFieldInfo &etfi = (*i).second;
		delete etfi.field;
	}

	delete recommended_attr_field;
	delete reply_status_field;
}

void nfs_packet_start(ExtentType::Ptr type)
{
	/* set all the nullable fields to null */
	FieldMap::iterator i;
	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
		ExtentTypeFieldInfo &etfi = (*i).second;
		if (etfi.nullable) {
			etfi.field->setNull();
		}
	}
}

void nfs_parse(field_info *fi)
{
	const gchar* abbrev = fi->hfinfo->abbrev;
	FieldMap::iterator it =	epan2dstype.find(abbrev);

	if (it == epan2dstype.end()) {
		if (ignored_fields.find(abbrev) == ignored_fields.end()) {
			fprintf(stderr,"unknown field %s\n", abbrev);
		}
		return;
	}

	assert (it != epan2dstype.end());

	ExtentTypeFieldInfo &etfi = (*it).second;
	ExtentType::fieldType ft = etfi.type;
	Field *field = etfi.field;

	switch(ft) {
	case ExtentType::ft_bool:
		((BoolField *)field)->set(true);
		break;

	case ExtentType::ft_byte:
		((ByteField *)field)->set(fi->value.value.sinteger);
		break;

	case ExtentType::ft_int32:
		((Int32Field *)field)->set(fi->value.value.sinteger);
		break;

	case ExtentType::ft_int64:
		((Int64Field *)field)->set(fi->value.value.integer64);
		break;

	case ExtentType::ft_double:
		((DoubleField *)field)->set(fi->value.value.floating);
		break;

	case ExtentType::ft_variable32:
		((Variable32Field *)field)->set(fi->value.value.ustring,
						fi->length);
		break;

	case ExtentType::ft_fixedwidth:
		{
			FixedWidthField *fwfield = (FixedWidthField *)field;
			fwfield->set(&fi->value.value.guid, fwfield->size());
			break;
		}

	default:
		assert(0);
	}
}
