/* protocol.c
 *
 * Routines for converting pcap files to DataSeries files
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

#include <protocol.hpp>

using namespace std;

void Protocol::add_proto_fields(const gchar *proto_name, int proto_name_strip_len,
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
