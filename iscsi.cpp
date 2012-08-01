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

const string iscsi_xml(
  "<ExtentType namespace=\"snsl.engr.uconn.edu\" name=\"Trace::iSCSI::SNSL\" version=\"1.0\" pack_null_compact=\"non_bool\"\n"
  " comment=\"note, if !garbage.isNull() then only the time field is valid.\" >\n"
  "  <field type=\"int64\" name=\"first_frame_time\" units=\"microseconds\" epoch=\"unix\" pack_relative=\"first_frame_time\" print_format=\"%llu\"/>\n"
  "  <field type=\"int64\" name=\"last_frame_time\" units=\"microseconds\" epoch=\"unix\" pack_relative=\"first_frame_time\"/>\n"
  "  <field type=\"int32\" name=\"source_ip\" print_format=\"%08X\"/>\n"
  "  <field type=\"int32\" name=\"source_port\" />\n"
  "  <field type=\"int32\" name=\"dest_ip\" print_format=\"%08X\"/>\n"
  "  <field type=\"int32\" name=\"dest_port\" />\n"
  "  <field type=\"byte\" name=\"cmd\" />\n"
  "  <field type=\"int32\" name=\"nt_status\" />\n"
  "  <field type=\"int32\" name=\"fid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fid.opened_in\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fid.closed_in\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fid.mapped_in\" opt_nullable=\"yes\" />\n"	// Starting to add iscsi properties after this line || N.B. Go back and check that the previous lines are needed
  "  <field type=\"byte\" name=\"opcode\" />\n"
  "  <field type=\"byte\" name=\"totalahslength\" />\n"
  "  <field type=\"int32\" name=\"datasegmentlength\" />\n"
  "  <field type=\"int32\" name=\"initiatortasktag\" />\n"
  "  <field type=\"variable32\" name=\"lun\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"I\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"targettransfertag\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"cmdsn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"expcmdsn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"statsn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"expstatsn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"datasn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"maxcmdsn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsicommand.F\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsicommand.R\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsicommand.W\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"scsicommand.attr\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"scsicommand.expecteddatatransferlength\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"immediatedata\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"r2tsn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"bufferOffset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"desireddatalength\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsidata.F\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"request_frame\" opt_nullable=\"yes\" />\n"
  "</ExtentType>\n"
  );

typedef struct {
	ExtentType::fieldType type;
	Field *field;
	bool nullable;
} ExtentTypeFieldInfo;

typedef tr1::unordered_map<string,ExtentTypeFieldInfo> FieldMap;
extern FieldMap epan2dstype;
extern set<string> ignored_fields;
extern set<string> special_case_fields;

extern FieldMap &map;
extern void add_proto_fields(const gchar *proto_name, int proto_name_strip_len,
	      FieldMap &map,
	      ExtentSeries& series,
	      ExtentType::Ptr type,
	      bool (*exception_handler)(const gchar*,
					const header_field_info*,
					ExtentSeries &series,
					FieldMap &map));

//static
//void add_proto_fields(const gchar *proto_name, int proto_name_strip_len,
//		      FieldMap &map,
//		      ExtentSeries& series,
//		      ExtentType::Ptr type,
//		      bool (*exception_handler)(const gchar*,
//						const header_field_info*,
//						ExtentSeries &series,
//						FieldMap &map))
//{
//	int proto_id = proto_get_id_by_filter_name(proto_name);
//	void *cookie;
//	header_field_info *hfinfo;
//
//	for (hfinfo = proto_get_first_protocol_field(proto_id, &cookie);
//	     hfinfo;
//	     hfinfo = proto_get_next_protocol_field(&cookie)) {
//
//		const gchar *epanFieldName = hfinfo->abbrev;
//		const gchar *extentFieldName =epanFieldName+proto_name_strip_len;
//
//		Field *field;
//
//		if (!type->hasColumn(extentFieldName)) {
//			fprintf(stderr, "Field %s does not exist in %s XML ExtentType Description\n", extentFieldName, proto_name);
//			continue;
//		}
//
//		if (exception_handler != NULL &&
//		    exception_handler(extentFieldName, hfinfo, series, map))
//			continue;
//
//		int flags = 0;
//		if (type->getNullable(extentFieldName))
//			flags = Field::flag_nullable;
//
//		ExtentType::fieldType ft = type->getFieldType(extentFieldName);
//
//		switch(ft) {
//		case ExtentType::ft_bool:
//			field = new BoolField(series, extentFieldName, flags);
//			assert(hfinfo->type == FT_BOOLEAN);
//			break;
//		case ExtentType::ft_byte:
//			field = new ByteField(series, extentFieldName, flags);
//			assert(hfinfo->type == FT_UINT8);
//			break;
//
//		case ExtentType::ft_int32:
//			field = new Int32Field(series, extentFieldName, flags);
//			assert(hfinfo->type == FT_UINT16 ||
//			       hfinfo->type == FT_FRAMENUM ||
//			       hfinfo->type == FT_UINT32);
//			break;
//
//		case ExtentType::ft_int64:
//			assert(hfinfo->type == FT_UINT64 ||
//			       hfinfo->type == FT_BYTES ||
//			       hfinfo->type == FT_ABSOLUTE_TIME ||
//			       hfinfo->type == FT_RELATIVE_TIME);
//			field = new Int64Field(series, extentFieldName, flags);
//			break;
//
//		case ExtentType::ft_double:
//			field = new DoubleField(series, extentFieldName, flags);
//			break;
//
//		case ExtentType::ft_variable32:
//			field = new Variable32Field(series, extentFieldName,
//						    flags);
//			break;
//
//		case ExtentType::ft_fixedwidth:
//			field = new FixedWidthField(series, extentFieldName,
//						    flags);
//			assert(hfinfo->type == FT_GUID);
//			break;
//
//		default:
//			assert(0);
//			break;
//		}
//
//		ExtentTypeFieldInfo &etfi = map[epanFieldName];
//		etfi.field = field;
//		etfi.type = ft;
//		etfi.nullable = (flags == Field::flag_nullable);
//	}
//}

//static Int32Field *recommended_attr_field;
//static Int32Field *reply_status_field;

static bool handle_iscsi_exception(const gchar *extentName,
				 const header_field_info *hfinfo,
				 ExtentSeries &series,
				 FieldMap &map)
{
//	if (strcmp(extentName,"attr") == 0) {
//		if (strcmp(hfinfo->name, "recc_attr")) {
//			recommended_attr_field =
//				new Int32Field(series, "recc_attr",
//					       Field::flag_nullable);
//			return true;
//		}
//	} else if (strcmp(extentName,"status") == 0) {
//		if (strcmp(hfinfo->name, "Status")) {
//			reply_status_field =
//				new Int32Field(series, "reply_status",
//					       Field::flag_nullable);
//			return true;
//		}
//	}

	return false;
}

const ExtentType::Ptr
iscsi_init(ExtentTypeLibrary& library, ExtentSeries& series)
{
	const ExtentType::Ptr type = library.registerTypePtr(iscsi_xml);
	series.setType(type);

	add_proto_fields("iscsi", 6, epan2dstype, series, type, handle_iscsi_exception);

	ignored_fields.insert("scsi.lun");
	ignored_fields.insert("scsi.inquiry.devtype");
	ignored_fields.insert("scsi.sbc.opcode");
	ignored_fields.insert("scsi.sbc.read.flags");
	ignored_fields.insert("scsi.sbc.wrprotect");
	ignored_fields.insert("scsi.dpo");
	ignored_fields.insert("scsi.fua");
	ignored_fields.insert("scsi.fua_nv");
	ignored_fields.insert("scsi.request_frame");
	ignored_fields.insert("scsi.sbc.rdwr10.lba");
	ignored_fields.insert("scsi.sbc.group");
	ignored_fields.insert("scsi.sbc.rdwr10.xferlen");
	ignored_fields.insert("scsi.sbc.opcode");
	ignored_fields.insert("scsi.sbc.dpo");
	ignored_fields.insert("scsi.sbc.fua");
	ignored_fields.insert("scsi.sbc.fua_nv");
	ignored_fields.insert("scsi.cdb.control");
	ignored_fields.insert("scsi.cdb.control.vendorspecific");
	ignored_fields.insert("scsi.cdb.control.reserved");
	ignored_fields.insert("scsi.cdb.control.naca");
	ignored_fields.insert("scsi.cdb.control.obs1");
	ignored_fields.insert("scsi.cdb.control.obs2");

	return type;
}

void iscsi_finish()
{

}

//void iscsi_packet_start(ExtentType::Ptr type)
//{
//	/* set all the nullable fields to null */
//	FieldMap::iterator i;
//	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
//		ExtentTypeFieldInfo &etfi = (*i).second;
//		if (etfi.nullable) {
//			etfi.field->setNull();
//		}
//	}
//}
//
//void iscsi_parse(field_info *fi)
//{
//	const gchar* abbrev = fi->hfinfo->abbrev;
//	FieldMap::iterator it =	epan2dstype.find(abbrev);
//
//	if (it == epan2dstype.end()) {
//		if (ignored_fields.find(abbrev) == ignored_fields.end()) {
//			fprintf(stderr,"unknown field %s\n", abbrev);
//		}
//		return;
//	}
//
//	assert (it != epan2dstype.end());
//
//	ExtentTypeFieldInfo &etfi = (*it).second;
//	ExtentType::fieldType ft = etfi.type;
//	Field *field = etfi.field;
//
//	switch(ft) {
//	case ExtentType::ft_bool:
//		((BoolField *)field)->set(true);
//		break;
//
//	case ExtentType::ft_byte:
//		((ByteField *)field)->set(fi->value.value.sinteger);
//		break;
//
//	case ExtentType::ft_int32:
//		((Int32Field *)field)->set(fi->value.value.sinteger);
//		break;
//
//	case ExtentType::ft_int64:
//		((Int64Field *)field)->set(fi->value.value.integer64);
//		break;
//
//	case ExtentType::ft_double:
//		((DoubleField *)field)->set(fi->value.value.floating);
//		break;
//
//	case ExtentType::ft_variable32:
//		((Variable32Field *)field)->set(fi->value.value.ustring,
//						fi->length);
//		break;
//
//	case ExtentType::ft_fixedwidth:
//		{
//			FixedWidthField *fwfield = (FixedWidthField *)field;
//			fwfield->set(&fi->value.value.guid, fwfield->size());
//			break;
//		}
//
//	default:
//		assert(0);
//	}
//}