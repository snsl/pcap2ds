/* iscsi.cpp
 *
 * Routines for converting iSCSI pcap files to DataSeries files
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
#include <iscsi.hpp>

using namespace std;

const string iscsi::iscsi_xml(
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
  "  <field type=\"int32\" name=\"fid.mapped_in\" opt_nullable=\"yes\" />\n"
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
  "  <field type=\"int64\" name=\"time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"data_in_frame\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"data_out_frame\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"response_frame\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"expdatasn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsidata.A\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsidata.O\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsidata.U\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsidata.S\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"scsidata.readresidualcount\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"scsiresponse.bidireadresidualcount\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"scsiresponse.residualcount\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"scsiresponse.response\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"scsiresponse.status\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsiresponse.o\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsiresponse.u\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsiresponse.O\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"scsiresponse.U\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"scsiresponse.senselength\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"keyvalue\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"login.status\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"login.T\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"login.C\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"login.csg\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"login.nsg\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"logout.reason\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"logout.response\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"tsih\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"isid.t\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"isid.a\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"isid.b\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"isid.c\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"isid.d\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"versionmin\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"versionmax\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"versionactive\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"padding\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"cid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"time2retain\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"time2wait\" opt_nullable=\"yes\" />\n"
  "</ExtentType>\n"
  );

bool iscsi::handle_iscsi_exception(const gchar *extentName,
				 const header_field_info *hfinfo,
				 ExtentSeries &series,
				 FieldMap &map)
{
	return false;
}

const ExtentType::Ptr
iscsi::init(ExtentTypeLibrary& library, ExtentSeries& series)
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
	ignored_fields.insert("scsi.sbc.blocksize");
	ignored_fields.insert("scsi.sbc.returned_lba");
	ignored_fields.insert("scsi.sbc.pmi");
	ignored_fields.insert("scsi.sbc.pmi_flags");
	ignored_fields.insert("scsi.sbc.readcapacity.lba");
	ignored_fields.insert("scsi.sbc.rdprotect");
	ignored_fields.insert("scsi.cdb.control");
	ignored_fields.insert("scsi.cdb.control.vendorspecific");
	ignored_fields.insert("scsi.cdb.control.reserved");
	ignored_fields.insert("scsi.cdb.control.naca");
	ignored_fields.insert("scsi.cdb.control.obs1");
	ignored_fields.insert("scsi.cdb.control.obs2");
	ignored_fields.insert("scsi.cdb.inq.control");
	ignored_fields.insert("scsi.cdb.alloclen");
	ignored_fields.insert("scsi.cdb.alloclen32");
	ignored_fields.insert("scsi.time");
	ignored_fields.insert("scsi.status");
	ignored_fields.insert("scsi.response_frame");
	ignored_fields.insert("scsi.sns.sksv");
	ignored_fields.insert("scsi.sns.fru");
	ignored_fields.insert("scsi.sns.ascq");
	ignored_fields.insert("scsi.sns.asc");
	ignored_fields.insert("scsi.sns.ascascq");
	ignored_fields.insert("scsi.sns.addlen");
	ignored_fields.insert("scsi.sns.info");
	ignored_fields.insert("scsi.sns.key");
	ignored_fields.insert("scsi.sns.errtype");
	ignored_fields.insert("scsi.spc.opcode");
	ignored_fields.insert("scsi.spc.select_report");
	ignored_fields.insert("scsi.inquiry.qualifier");
	ignored_fields.insert("scsi.inquiry.control.obs1");
	ignored_fields.insert("scsi.inquiry.control.obs2");
	ignored_fields.insert("scsi.inquiry.control.naca");
	ignored_fields.insert("scsi.inquiry.control.reserved");
	ignored_fields.insert("scsi.inquiry.control.vendorspecific");
	ignored_fields.insert("scsi.inquiry.flags");
	ignored_fields.insert("scsi.inquiry.evpd.pagecode");
	ignored_fields.insert("scsi.inquiry.version_desc");
	ignored_fields.insert("scsi.inquiry.reserved");
	ignored_fields.insert("scsi.inquiry.vendor_specific");
	ignored_fields.insert("scsi.inquiry.product_rev");
	ignored_fields.insert("scsi.inquiry.product_id");
	ignored_fields.insert("scsi.inquiry.vendor_id");
	ignored_fields.insert("scsi.inquiry.cmdque");
	ignored_fields.insert("scsi.inquiry.linked");
	ignored_fields.insert("scsi.inquiry.sync");
	ignored_fields.insert("scsi.inquiry.reladr");
	ignored_fields.insert("scsi.inquiry.reladrflags");
	ignored_fields.insert("scsi.inquiry.mchngr");
	ignored_fields.insert("scsi.inquiry.multip");
	ignored_fields.insert("scsi.inquiry.encserv");
	ignored_fields.insert("scsi.inquiry.bque");
	ignored_fields.insert("scsi.inquiry.bqueflags");
	ignored_fields.insert("scsi.inquiry.protect");
	ignored_fields.insert("scsi.inquiry.tpc");
	ignored_fields.insert("scsi.inquiry.tpgs");
	ignored_fields.insert("scsi.inquiry.acc");
	ignored_fields.insert("scsi.inquiry.sccs");
	ignored_fields.insert("scsi.inquiry.sccsflags");
	ignored_fields.insert("scsi.inquiry.add_len");
	ignored_fields.insert("scsi.inquiry.rdf");
	ignored_fields.insert("scsi.inquiry.hisup");
	ignored_fields.insert("scsi.inquiry.normaca");
	ignored_fields.insert("scsi.inquiry.trmtsk");
	ignored_fields.insert("scsi.inquiry.aerc");
	ignored_fields.insert("scsi.inquiry.acaflags");
	ignored_fields.insert("scsi.inquiry.version");
	ignored_fields.insert("scsi.inquiry.removable");
	ignored_fields.insert("scsi.inquiry.rmbflags");
	ignored_fields.insert("scsi.inquiry.peripheral");
	ignored_fields.insert("scsi.mode.sbc.pagecode");
	ignored_fields.insert("scsi.mode.spc.pagecode");
	ignored_fields.insert("scsi.mode.pc");
	ignored_fields.insert("scsi.mode.flags");
	ignored_fields.insert("scsi.reportluns.lun");

	return type;
}

void iscsi::finish()
{

}

void iscsi::packet_start(ExtentType::Ptr type)
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

void iscsi::parse(field_info *fi)
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
