/* nfs.cpp
 *
 * Routines for converting NFS pcap files to DataSeries files
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
#include <nfs.hpp>

using namespace std;

Int32Field * nfs::recommended_attr_field;
Int32Field * nfs::reply_status_field;

const string nfs::nfs_xml(
  "<ExtentType namespace=\"snsl.engr.uconn.edu\" name=\"Trace::NFS::SNSL\" version=\"1.0\" pack_null_compact=\"non_bool\"\n"
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
  "  <field type=\"int32\" name=\"procedure_v4\" />\n"
  "  <field type=\"variable32\" name=\"tag\" />\n"
  "  <field type=\"int32\" name=\"minorversion\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"ops.count\" />\n"
  "  <field type=\"int32\" name=\"opcode\" />\n"
  "  <field type=\"int32\" name=\"main_opcode\" />\n"
  "  <field type=\"byte\" name=\"access_check\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_read\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_modify\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_extend\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_execute\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"access_rights\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_denied\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_lookup\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_delete\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"access_supported\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_supp_read\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_supp_modify\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_supp_extend\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_supp_execute\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_supp_lookup\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access_supp_delete\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fh.length\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fh.hash\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"fhandle\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"attr\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"recc_attr\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"nfsstat4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"status\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"reply_status\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"nfs_ftype4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"change_info.atomic\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"changeid4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"changeid4.before\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"changeid4.after\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"nfs_client_id4.id\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"stateid4.hash\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"stateid4.other\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"fattr4_owner\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"fattr4_owner_group\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fattr4_link_support\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fattr4_symlink_support\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fattr4.aclsupport\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fattr4.size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fattr4.fileid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fattr4.numlinks\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fattr4.space_used\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fattr4.mounted_on_fileid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"fattr4.attr_vals\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fattr4.lease_time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fattr4.maxfilesize\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fattr4.maxread\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fattr4.maxwrite\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fattr4.maxlink\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fattr4.maxname\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fsid4.major\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"fsid4.minor\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"specdata1\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"specdata2\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"nfstime4.seconds\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"nfstime4.nseconds\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"pathname.component\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"verifier4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"cookie4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"cookieverf4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"dircount\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"maxcount\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"dirlist4.eof\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"seqid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"open.delegation_type\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"open.opentype\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"open.claim_type\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"set_it\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"offset4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"count4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"open4.share_access\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"open4.share_deny\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"clientid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"open_owner4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"createmode4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"stable_how4\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"read.data_length\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"write.data_length\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"data\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"eof\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"cb_program\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"r_netid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"r_addr\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"callback.ident\" opt_nullable=\"yes\" />\n"
  "</ExtentType>\n"
  );

bool nfs::handle_nfs_exception(const gchar *extentName,
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
nfs::init(ExtentTypeLibrary& library, ExtentSeries& series)
{
	const ExtentType::Ptr type = library.registerTypePtr(nfs_xml);
	series.setType(type);

	add_proto_fields("nfs", 4, epan2dstype, series, type, handle_nfs_exception);

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

void nfs::finish()
{
	FieldMap::iterator i;
	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
		ExtentTypeFieldInfo &etfi = (*i).second;
		delete etfi.field;
	}

	delete recommended_attr_field;
	delete reply_status_field;
}

void nfs::packet_start(ExtentType::Ptr type)
{
	/* set all the nullable fields to null */
	FieldMap::iterator i;
	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
		ExtentTypeFieldInfo &etfi = (*i).second;
		if (etfi.nullable) {
			etfi.field->setNull();
		}
	}

	recommended_attr_field->setNull();
	reply_status_field->setNull();
}

void nfs::parse(field_info *fi)
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
