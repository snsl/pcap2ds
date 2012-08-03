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

const ExtentType::Ptr smb_init(ExtentTypeLibrary& library, ExtentSeries& series);
const ExtentType::Ptr nfs_init(ExtentTypeLibrary& library, ExtentSeries& series);
const ExtentType::Ptr iscsi_init(ExtentTypeLibrary& library, ExtentSeries& series);

extern string packet_type;

void smb_parse(const gchar* abbrev, field_info *fi, Field *field, ExtentType::fieldType *ft);

void smb_finish();
void nfs_finish();
void iscsi_finish();

typedef struct {
	ExtentType::fieldType type;
	Field *field;
	bool nullable;
} ExtentTypeFieldInfo;

typedef tr1::unordered_map<string,ExtentTypeFieldInfo> FieldMap;	// Can put in .h file somewhere
//static
FieldMap epan2dstype;
set<string> ignored_fields;	// Try to see if can work this from each individual cpp file
// May need to extern || Do as Classes/Objects
set<string> special_case_fields;

//static
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
			fprintf(stderr, "Field %s does not exist in %s XML ExtentType Description\n", extentFieldName, proto_name);
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

const ExtentType::Ptr
dissect_init(ExtentTypeLibrary& library, ExtentSeries& series, string packet_type)
{
	if(strcmp(packet_type.c_str(), "smb") == 0)
	{
		const ExtentType::Ptr type = smb_init(library, series);
		return type;
	}
	else if(strcmp(packet_type.c_str(), "nfs") == 0)
	{
		const ExtentType::Ptr type = nfs_init(library, series);
		return type;
	}
	else if(strcmp(packet_type.c_str(), "iscsi") == 0)
	{
		const ExtentType::Ptr type = iscsi_init(library, series);
		return type;
	}
}

void dissect_finish(string packet_type)
{
	FieldMap::iterator i;
	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
		ExtentTypeFieldInfo &etfi = (*i).second;
		delete etfi.field;
	}

	if(strcmp(packet_type.c_str(), "smb") == 0)
		smb_finish();
	else if(strcmp(packet_type.c_str(), "nfs") == 0)
		nfs_finish();
	else if(strcmp(packet_type.c_str(), "iscsi") == 0)
		iscsi_finish();
}

void dissect_packet_start(ExtentType::Ptr type)
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

void dissect_parse(field_info *fi, string packet_type)
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

	//Handle smb offest exception
    if(packet_type == "smb")
    	smb_parse(abbrev, fi, field, &ft);

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
