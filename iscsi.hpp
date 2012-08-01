/* iscsi.hpp
 *
 * Definitions for converting iSCSI pcap files to DataSeries files
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

/*------------------------------------------------------------------
 * Definition of subclass iscsi, built from the Protocol class
 *------------------------------------------------------------------*/
class iscsi : public Protocol{
protected:
	static const string iscsi_xml;
	static bool handle_iscsi_exception(const gchar *extentName,
					 const header_field_info *hfinfo,
					 ExtentSeries &series,
					 FieldMap &map);
public:
	const ExtentType::Ptr init(ExtentTypeLibrary& library, ExtentSeries& series);
	void finish();
	void packet_start(ExtentType::Ptr type);
	void parse(field_info *fi);
};
