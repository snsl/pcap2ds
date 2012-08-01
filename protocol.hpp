/* protocol.hpp
 *
 * Definitions for Protocol Class
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
#ifndef __DISSECT_PROTOCOL_H
#define __DISSECT_PROTOCOL_H

#include <string>
#include <set>
#include <tr1/unordered_map>

#include <DataSeries/DataSeriesModule.hpp>
extern "C" {
#include "config.h"
#include <epan/proto.h>
}

#include <DataSeries/ExtentType.hpp>

using namespace std;

/*-----------------------------------------------------
 * Definition of the main class Protocol
 *------------------------------------------------------*/
class Protocol
{
protected:
	typedef struct {
		ExtentType::fieldType type;
		Field *field;
		bool nullable;
	} ExtentTypeFieldInfo;

	typedef tr1::unordered_map<string,ExtentTypeFieldInfo> FieldMap;	// Can put in .h file somewhere

	FieldMap epan2dstype;
	set<string> ignored_fields;	// Try to see if can work this from each individual cpp file
	set<string> special_case_fields;

public:
	virtual const ExtentType::Ptr init(ExtentTypeLibrary& library, ExtentSeries& series) = 0;
	virtual void packet_start(ExtentType::Ptr type) = 0;
	virtual void parse(field_info *fi) = 0;
	virtual void finish() = 0;
	void add_proto_fields(const gchar *proto_name, int proto_name_strip_len,
		      FieldMap &map,
		      ExtentSeries& series,
		      ExtentType::Ptr type,
		      bool (*exception_handler)(const gchar*,
						const header_field_info*,
						ExtentSeries &series,
						FieldMap &map));

	// According to wiki, polymorphic deletes require a virtual base destructor
	virtual ~Protocol(){
	}
};

#endif
