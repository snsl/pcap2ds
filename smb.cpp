#include <string>
#include <set>
#include <tr1/unordered_map>

#include <DataSeries/DataSeriesModule.hpp>
extern "C" {
#include "config.h"
#include <epan/proto.h>
}


using namespace std;

const string smb_xml(
  "<ExtentType namespace=\"snsl.engr.uconn.edu\" name=\"Trace::SMB::SNSL\" version=\"1.0\" pack_null_compact=\"non_bool\"\n"
  " comment=\"note, if !garbage.isNull() then only the time field is valid.\" >\n"
  "  <field type=\"int64\" name=\"first_frame_time\" units=\"microseconds\" epoch=\"unix\" pack_relative=\"first_frame_time\"/>\n"
  "  <field type=\"int64\" name=\"last_frame_time\" units=\"microseconds\" epoch=\"unix\" pack_relative=\"first_frame_time\"/>\n"
  "  <field type=\"int32\" name=\"source_ip\" />\n"
  "  <field type=\"int32\" name=\"source_port\" />\n"
  "  <field type=\"int32\" name=\"dest_ip\" />\n"
  "  <field type=\"int32\" name=\"dest_port\" />\n"
  "  <field type=\"byte\" name=\"cmd\" />\n"
  "  <field type=\"int32\" name=\"nt_status\" />\n"
  "  <field type=\"int32\" name=\"fid\" />\n"
  "  <field type=\"int32\" name=\"fid.opened_in\" />\n"
  "  <field type=\"int32\" name=\"fid.closed_in\" />\n"
  "  <field type=\"int32\" name=\"fid.mapped_in\" />\n"
  "  <field type=\"bool\" name=\"flags.response\" />\n"
  "  <field type=\"bool\" name=\"flags.notify\" />\n"
  "  <field type=\"bool\" name=\"flags.oplock\" />\n"
  "  <field type=\"bool\" name=\"flags.canon\" />\n"
  "  <field type=\"bool\" name=\"flags.receive_buffer\" />\n"
  "  <field type=\"bool\" name=\"flags.lock\" />\n"
  "  <field type=\"bool\" name=\"flags.caseless\" />\n"
  "  <field type=\"bool\" name=\"flags2.string\" />\n"
  "  <field type=\"bool\" name=\"flags2.nt_error\" />\n"
  "  <field type=\"bool\" name=\"flags2.roe\" />\n"
  "  <field type=\"bool\" name=\"flags2.dfs\" />\n"
  "  <field type=\"bool\" name=\"flags2.esn\" />\n"
  "  <field type=\"bool\" name=\"flags2.reparse_path\" />\n"
  "  <field type=\"bool\" name=\"flags2.long_names_used\" />\n"
  "  <field type=\"bool\" name=\"flags2.sec_sig_required\" />\n"
  "  <field type=\"bool\" name=\"flags2.compressed\" />\n"
  "  <field type=\"bool\" name=\"flags2.sec_sig\" />\n"
  "  <field type=\"bool\" name=\"flags2.ea\" />\n"
  "  <field type=\"bool\" name=\"flags2.long_names_allowed\" />\n"
  "  <field type=\"int32\" name=\"pid.high\" />\n"
  "  <field type=\"int64\" name=\"signature\" />\n"
  "  <field type=\"int64\" name=\"file.rw.offset\" />\n"
  "  <field type=\"int32\" name=\"file.rw.length\" />\n"
  "  <field type=\"int32\" name=\"count_low\" />\n"
  "  <field type=\"int32\" name=\"count_high\" />\n"
  "  <field type=\"int32\" name=\"tid\" />\n"
  "  <field type=\"int32\" name=\"pid\" />\n"
  "  <field type=\"int32\" name=\"uid\" />\n"
  "  <field type=\"int32\" name=\"mid\" />\n"
  "  <field type=\"byte\" name=\"wct\" />\n"
  "  <field type=\"int32\" name=\"bcc\" />\n"
  "  <field type=\"int32\" name=\"access_mask\" />\n"
  "  <field type=\"int32\" name=\"create_flags\" />\n"
  "  <field type=\"variable32\" name=\"path\" />\n"
  "  <field type=\"int32\" name=\"timeout\" />\n"
  "  <field type=\"int64\" name=\"alloc_size64\" />\n"
  "  <field type=\"int32\" name=\"alloc_size\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.encrypted\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.not_content_indexed\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.offline\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.compressed\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.reparse\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.sparse\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.temporary\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.normal\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.device\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.directory\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.volume\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.system\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.hidden\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.read_only\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.archive\" />\n"
  "  <field type=\"bool\" name=\"access.generic_read\" />\n"
  "  <field type=\"bool\" name=\"access.generic_write\" />\n"
  "  <field type=\"bool\" name=\"access.generic_execute\" />\n"
  "  <field type=\"bool\" name=\"access.generic_all\" />\n"
  "  <field type=\"bool\" name=\"access.maximum_allowed\" />\n"
  "  <field type=\"bool\" name=\"access.system_security\" />\n"
  "  <field type=\"bool\" name=\"access.synchronize\" />\n"
  "  <field type=\"bool\" name=\"access.write_owner\" />\n"
  "  <field type=\"bool\" name=\"access.write_dac\" />\n"
  "  <field type=\"bool\" name=\"access.read_control\" />\n"
  "  <field type=\"bool\" name=\"access.delete\" />\n"
  "  <field type=\"bool\" name=\"access.write_attributes\" />\n"
  "  <field type=\"bool\" name=\"access.read_attributes\" />\n"
  "  <field type=\"bool\" name=\"access.delete_child\" />\n"
  "  <field type=\"bool\" name=\"access.execute\" />\n"
  "  <field type=\"bool\" name=\"access.write_ea\" />\n"
  "  <field type=\"bool\" name=\"access.read_ea\" />\n"
  "  <field type=\"bool\" name=\"access.append\" />\n"
  "  <field type=\"bool\" name=\"access.write\" />\n"
  "  <field type=\"bool\" name=\"access.read\" />\n"
  "  <field type=\"int64\" name=\"access.time\" />\n"
  "  <field type=\"bool\" name=\"nt.create.ext\" />\n"
  "  <field type=\"bool\" name=\"nt.create.dir\" />\n"
  "  <field type=\"bool\" name=\"nt.create.batch_oplock\" />\n"
  "  <field type=\"bool\" name=\"nt.create.oplock\" />\n"
  "  <field type=\"bool\" name=\"share.access.delete\" />\n"
  "  <field type=\"bool\" name=\"share.access.write\" />\n"
  "  <field type=\"bool\" name=\"share.access.read\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.directory\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.write_through\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.sequential_only\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.intermediate_buffering\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.sync_io_alert\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.sync_io_nonalert\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.non_directory\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.create_tree_connection\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.complete_if_oplocked\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.no_ea_knowledge\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.eight_dot_three_only\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.random_access\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.delete_on_close\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.open_by_fileid\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.backup_intent\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.no_compression\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.reserve_opfilter\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.open_reparse_point\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.open_no_recall\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.open_for_free_space_query\" />\n"
  "  <field type=\"int32\" name=\"nt.function\" />\n"
  "  <field type=\"int32\" name=\"create_options\" />\n"
  "  <field type=\"int32\" name=\"create.disposition\" />\n"
  "  <field type=\"int64\" name=\"current_offset\" />\n"
  "  <field type=\"int32\" name=\"offset\" />\n"
  "  <field type=\"int32\" name=\"offset_high\" />\n"
  "  <field type=\"int32\" name=\"rfid\" />\n"
  "  <field type=\"int32\" name=\"pwlen\" />\n"
  "  <field type=\"variable32\" name=\"password\" />\n"
  "  <field type=\"int32\" name=\"connect.flags\" />\n"
  "  <field type=\"variable32\" name=\"service\" />\n"
  "  <field type=\"int32\" name=\"andxoffset\" />\n"
  "  <field type=\"int32\" name=\"connect.support\" />\n"
  "  <field type=\"int32\" name=\"andx.maximal_access_rights\" />\n"
  "  <field type=\"int32\" name=\"andx.guest_access_rights\" />\n"
  "  <field type=\"int32\" name=\"impersonation_level\" />\n"
  "  <field type=\"int32\" name=\"security.flags\" />\n"
  "  <field type=\"int32\" name=\"remaining\" />\n"
  "  <field type=\"int32\" name=\"data_len_high\" />\n"
  "  <field type=\"int32\" name=\"data_len_low\" />\n"
  "  <field type=\"int32\" name=\"data_offset\" />\n"
  "  <field type=\"int32\" name=\"data_offset32\" />\n"
  "  <field type=\"int32\" name=\"data_disp\" />\n"
  "  <field type=\"int32\" name=\"close.fid\" />\n"
  "  <field type=\"bool\" name=\"write.mode.write_through\" />\n"
  "  <field type=\"int32\" name=\"dcm\" />\n"
  "  <field type=\"int32\" name=\"link_count\" />\n"
  "  <field type=\"int32\" name=\"maxcount_low\" />\n"
  "  <field type=\"int32\" name=\"mincount\" />\n"
  "  <field type=\"int32\" name=\"maxcount_high\" />\n"
  "  <field type=\"bool\" name=\"transaction.flags.owt\" />\n"
  "  <field type=\"bool\" name=\"transaction.flags.dtid\" />\n"
  "  <field type=\"variable32\" name=\"trans.name\" />\n"
  "  <field type=\"int32\" name=\"tpc\" />\n"
  "  <field type=\"int32\" name=\"tdc\" />\n"
  "  <field type=\"int32\" name=\"mpc\" />\n"
  "  <field type=\"int32\" name=\"mdc\" />\n"
  "  <field type=\"byte\" name=\"msc\" />\n"
  "  <field type=\"int32\" name=\"pc\" />\n"
  "  <field type=\"int32\" name=\"po\" />\n"
  "  <field type=\"int32\" name=\"dc\" />\n"
  "  <field type=\"byte\" name=\"sc\" />\n"
  "  <field type=\"byte\" name=\"is_directory\" />\n"
  "  <field type=\"int32\" name=\"delete_pending\" />\n"
  "  <field type=\"int32\" name=\"pd\" />\n"
  "  <field type=\"int32\" name=\"trans2.cmd\" />\n"
  "  <field type=\"variable32\" name=\"file\" />\n"
  "  <field type=\"int32\" name=\"trans2.flags\" />\n"
  "  <field type=\"int32\" name=\"qpi_loi\" />\n"
  "  <field type=\"int32\" name=\"trans2.qpi.file\" />\n"
  "  <field type=\"int32\" name=\"ea.error_offset\" />\n"
  "  <field type=\"int64\" name=\"time\" />\n"
  "  <field type=\"int64\" name=\"create.time\" />\n"
  "  <field type=\"int64\" name=\"change.time\" />\n"
  "  <field type=\"int64\" name=\"last_write.time\" />\n"
  "  <field type=\"int64\" name=\"end_of_file\" />\n"
  "  <field type=\"int32\" name=\"change_time\" />\n"
  "  <field type=\"int32\" name=\"share_access\" />\n"
  "  <field type=\"bool\" name=\"connect.flags.dtid\" />\n"
  "  <field type=\"bool\" name=\"connect.flags.extendedresp\" />\n"
  "  <field type=\"bool\" name=\"connect.flags.extendedsig\" />\n"
  "  <field type=\"int32\" name=\"connect.support.cscmask\" />\n"
  "  <field type=\"bool\" name=\"connect.support.dfs\" />\n"
  "  <field type=\"bool\" name=\"connect.support.extendedsig\" />\n"
  "  <field type=\"bool\" name=\"connect.support.search\" />\n"
  "  <field type=\"bool\" name=\"connect.support.uniqfilename\" />\n"
  "  <field type=\"int32\" name=\"create.action\" />\n"
  "  <field type=\"int64\" name=\"create.file_id_64b\" />\n"
  "  <field type=\"int32\" name=\"ea.list_length\" />\n"
  "  <field type=\"int32\" name=\"end_of_search\" />\n"
  "  <field type=\"byte\" name=\"error_class\" />\n"
  "  <field type=\"int32\" name=\"error_code\" />\n"
  "  <field type=\"int32\" name=\"ff2_loi\" />\n"
  "  <field type=\"int32\" name=\"file_index\" />\n"
  "  <field type=\"int32\" name=\"file_name_len\" />\n"
  "  <field type=\"int32\" name=\"file_type\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.backup\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.close\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.continue\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.eos\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.resume\" />\n"
  "  <field type=\"int64\" name=\"free_alloc_units\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.cpn\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.css\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.fc\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.ns\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.pacls\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.rov\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.se\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.sla\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.soids\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.srp\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.srs\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.ssf\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.uod\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.vis\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.vq\" />\n"
  "  <field type=\"int32\" name=\"fs_bytes_per_sector\" />\n"
  "  <field type=\"int32\" name=\"fs_max_name_len\" />\n"
  "  <field type=\"int32\" name=\"fs_name.len\" />\n"
  "  <field type=\"variable32\" name=\"fs_name\" />\n"
  "  <field type=\"int32\" name=\"fs_sector_per_unit\" />\n"
  "  <field type=\"int32\" name=\"impersonation.level\" />\n"
  "  <field type=\"int64\" name=\"index_number\" />\n"
  "  <field type=\"int32\" name=\"ipc_state.endpoint\" />\n"
  "  <field type=\"int32\" name=\"ipc_state.icount\" />\n"
  "  <field type=\"bool\" name=\"ipc_state.nonblocking\" />\n"
  "  <field type=\"int32\" name=\"ipc_state.pipe_type\" />\n"
  "  <field type=\"int32\" name=\"ipc_state.read_mode\" />\n"
  "  <field type=\"int32\" name=\"last_name_offset\" />\n"
  "  <field type=\"bool\" name=\"lock.type.cancel\" />\n"
  "  <field type=\"bool\" name=\"lock.type.change\" />\n"
  "  <field type=\"bool\" name=\"lock.type.large\" />\n"
  "  <field type=\"bool\" name=\"lock.type.oplock_release\" />\n"
  "  <field type=\"bool\" name=\"lock.type.shared\" />\n"
  "  <field type=\"int32\" name=\"locking.num_locks\" />\n"
  "  <field type=\"int32\" name=\"locking.num_unlocks\" />\n"
  "  <field type=\"byte\" name=\"locking.oplock.level\" />\n"
  "  <field type=\"int32\" name=\"next_entry_offset\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.attributes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.creation\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.dir_name\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.ea\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.file_name\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.last_access\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.last_write\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.security\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.size\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.stream_name\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.stream_size\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.stream_write\" />\n"
  "  <field type=\"byte\" name=\"nt.notify.watch_tree\" />\n"
  "  <field type=\"byte\" name=\"oplock.level\" />\n"
  "  <field type=\"int32\" name=\"qfsi_loi\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.archive\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.directory\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.hidden\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.read_only\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.system\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.volume\" />\n"
  "  <field type=\"int32\" name=\"search_count\" />\n"
  "  <field type=\"int32\" name=\"search_id\" />\n"
  "  <field type=\"variable32\" name=\"search_pattern\" />\n"
  "  <field type=\"bool\" name=\"security.flags.context_tracking\" />\n"
  "  <field type=\"bool\" name=\"security.flags.effective_only\" />\n"
  "  <field type=\"variable32\" name=\"short_file\" />\n"
  "  <field type=\"int32\" name=\"short_file_name_len\" />\n"
  "  <field type=\"int32\" name=\"spi_loi\" />\n"
  "  <field type=\"int32\" name=\"storage_type\" />\n"
  "  <field type=\"variable32\" name=\"trans_name\" />\n"
  "  <field type=\"variable32\" name=\"volume_guid\" />\n"
  "  <field type=\"bool\" name=\"write.mode.message_start\" />\n"
  "  <field type=\"bool\" name=\"write.mode.raw\" />\n"
  "  <field type=\"bool\" name=\"write.mode.return_remaining\" />\n"
  "  <field type=\"int32\" name=\"pipe.function\" />\n"
  "  <field type=\"int32\" name=\"pipe.priority\" />\n"
  "</ExtentType>\n"
  );

const string smb_epanfields[] = {
	"smb.cmd", "cmd",
	"smb.nt_status", "nt_status",
	"smb.flags", "flags",
	"smb.flags2", "flags2",
	"smb.flags2", "flags2",
	"smb.pid.high", "pid.high",
	"smb.signature", "signature",
	"smb.tid", "tid",
	"smb.pid", "pid",
	"smb.uid", "uid",
	"smb.mid", "mid",
	"smb.wct", "wct",
	"smb.bcc", "bcc",
	"smb.access_mask", "access_mask",
	"smb.create_flags", "create_flags",
	"smb.timeout", "timeout",
	"smb.alloc_size", "alloc_size",
	"smb.fileattr", "fileattr",
	"smb.share_access", "share_access",
	"smb.create_options", "create_options",
	"smb.offset", "offset",
	"smb.create.disposition", "create.disposition",
	"smb.rfid", "rfid",
	"smb.password", "password",
	"smb.pwlen", "pwlen",
	"smb.andxoffset", "andx.offset",
	"smb.connect.flags", "connect.flags",
	"smb.service", "service",
	"smb.connect.support", "connect.support",
	"smb.impersonation_level", "impersonation_level",
	"smb.security.flags", "security.flags",
	"smb.write.mode", "write.mode",
	"smb.remaining", "remaining",
	"smb.data_len_high", "data_len_high",
	"smb.data_len_low", "data_len_low",
	"smb.data_offset", "data_offset",
	"smb.write.offset_high", "write.offset_high",
	"smb.close.fid", "close.fid",
	"smb.read.maxcount_low", "read.maxcount_low",
	"smb.read.mincount", "read.mincount",
	"smb.read.dcm", "read.dcm",
	"smb.read.maxcount_high", "read.maxcount_high",
	"smb.read.offset_high", "read.offset_high",
	"smb.trans.flags", "trans.flags",
	"smb.trans.name", "trans.name",
	"smb.tpc", "trans.tpc",
	"smb.tdc", "trans.tdc",
	"smb.mpc", "trans.mpc",
	"smb.mdc", "trans.mdc",
	"smb.msc", "trans.msc",
	"smb.pc", "trans.pc",
	"smb.po", "trans.po",
	"smb.dc", "trans.dc",
	"smb.data_offset", "trans.data_offset",
	"smb.data_disp", "trans.data_disp",
	"smb.sc", "trans.sc",
	"smb.trans2.cmd", "trans2.cmd",
	"smb.trans2.flags", "trans2.flags",
	"smb.trans2.file", "trans2.file",
	"smb.trans2.qpi.loi", "trans2.qpi.loi",
	"smb.trans2.qpi.file", "trans2.qpi.file",
	"smb.trans2.qpi.qpi.ea.error_offset", "trans2.qpi.ea.error_offset",
	"smb.trans2.qpi.create_time", "trans2.qpi.create_time",
	"smb.trans2.qpi.access_time", "trans2.qpi.access_time",
	"smb.trans2.qpi.last_write_time", "trans2.qpi.last_write_time",
	"smb.trans2.qpi.change_time", "trans2.qpi.change_time"
};

typedef struct {
	ExtentType::fieldType type;
	Field *field;
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

//	int numfields = sizeof(smb_epanfields)/2/sizeof(smb_epanfields[0]);
//	for (int i=0; i<numfields; i++) {
//		string epanFieldName = smb_epanfields[2*i];
//		string extentName = smb_epanfields[2*i+1];
	for (hfinfo = proto_get_first_protocol_field(proto_id, &cookie);
	     hfinfo;
	     hfinfo = proto_get_next_protocol_field(&cookie)) {

		const gchar *epanFieldName = hfinfo->abbrev;
		const gchar *extentName = epanFieldName+proto_name_strip_len;

		Field *field;

		if (!type->hasColumn(extentName)) {
			fprintf(stderr, "Field %s does not exist in SMB XML ExtentType Description\n", extentName);
			continue;
		}

		if (exception_handler != NULL &&
		    exception_handler(extentName,hfinfo,series,map))
			continue;

		ExtentType::fieldType ft = type->getFieldType(extentName);
		switch(ft) {
		case ExtentType::ft_bool:
			field = new BoolField(series, extentName);
			assert(hfinfo->type == FT_BOOLEAN);
			break;

		case ExtentType::ft_byte:
			field = new ByteField(series, extentName);
			assert(hfinfo->type == FT_UINT8);
			break;

		case ExtentType::ft_int32:
			field = new Int32Field(series, extentName);
			assert(hfinfo->type == FT_UINT16 ||
			       hfinfo->type == FT_FRAMENUM ||
			       hfinfo->type == FT_UINT32);
			break;

		case ExtentType::ft_int64:
			assert(hfinfo->type == FT_UINT64 ||
			       hfinfo->type == FT_BYTES ||
			       hfinfo->type == FT_ABSOLUTE_TIME ||
			       hfinfo->type == FT_RELATIVE_TIME);
			field = new Int64Field(series, extentName);
			break;

		case ExtentType::ft_double:
			field = new DoubleField(series, extentName);
			break;

		case ExtentType::ft_variable32:
			field = new Variable32Field(series, extentName);
			break;

		case ExtentType::ft_fixedwidth:
			field = new FixedWidthField(series, extentName);
			assert(hfinfo->type == FT_BYTES);
			break;

		default:
			assert(0);
			break;
		}

		ExtentTypeFieldInfo &etfi = map[epanFieldName];
		etfi.field = field;
		etfi.type = ft;
	}
}

static Int64Field *current_offset_field;
static Int64Field *alloc_size64_field;

static bool handle_smb_exception(const gchar *extentName,
				 const header_field_info *hfinfo,
				 ExtentSeries &series,
				 FieldMap &map)
{
	if (strcmp(extentName,"offset") == 0) {
		if (hfinfo->type == FT_UINT64) {
			current_offset_field =
					new Int64Field(series, "current_offset");
			return true;
		}
	} else if (strcmp(extentName,"alloc_size") == 0) {
		if (hfinfo->type == FT_UINT64) {
			alloc_size64_field =
				new Int64Field(series, "alloc_size64");
			return true;
		}
	} else if (strcmp(extentName,"dc") == 0) {
		if (map.find("smb.dc") != map.end())
			return true;
	} else if (strcmp(extentName,"pd") == 0) {
		if (map.find("smb.pd") != map.end())
			return true;
	} else if (strcmp(extentName,"pc") == 0) {
		if (map.find("smb.pc") != map.end())
			return true;
	} else if (strcmp(extentName,"po") == 0) {
		if (map.find("smb.po") != map.end())
			return true;
	} else if (strcmp(extentName,"data_disp") == 0) {
		if (map.find("smb.data_disp") != map.end())
			return true;
	} else if (strcmp(extentName,"data_offset") == 0) {
		if (map.find("smb.data_offset") != map.end())
			return true;
	} else if (strncmp(extentName,"file_attribute.",15) == 0) {
		const gchar* attrs[] = { "read_only", "hidden", "system",
					 "volume", "directory", "archive",
					 "device", "normal", "temporary",
					 "sparse", "reparse", "compressed",
					 "offline", "not_content_indexed",
					 "encrypted"
		};

		int numattrs = sizeof(attrs)/sizeof(gchar*);
		for (int i=0; i<numattrs; i++) {
			if (strcmp(&extentName[15], attrs[i]) == 0) {
				string epanName = "smb.file_attribute.";
				epanName = epanName + attrs[i];
				return (map.find(epanName) != map.end());
			}
		}
	}
	return false;
}

const ExtentType::Ptr
smb_init(ExtentTypeLibrary& library, ExtentSeries& series)
{
	const ExtentType::Ptr type = library.registerTypePtr(smb_xml);
	series.setType(type);

	add_proto_fields("smb", 4, epan2dstype, series, type, handle_smb_exception);
	add_proto_fields("pipe", 0, epan2dstype, series, type, NULL);

	ignored_fields.insert("smb.reserved");
	ignored_fields.insert("smb.padding");
	ignored_fields.insert("smb.unknown_data");
	ignored_fields.insert("smb.response_to");

	return type;
}

void smb_finish()
{
	FieldMap::iterator i;
	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
		ExtentTypeFieldInfo &etfi = (*i).second;
		delete etfi.field;
	}
	delete current_offset_field;
	delete alloc_size64_field;
}

void smb_parse(field_info *fi, const string value)
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

	// handle offset special case
	if (strcmp(abbrev,"smb.offset") == 0) {
		if (fi->hfinfo->type == FT_UINT64) {
			field = current_offset_field;
			ft = ExtentType::ft_int64;
		}
	} else if (strcmp(abbrev,"smb.alloc_size") == 0) {
		if (fi->hfinfo->type == FT_UINT64) {
			field = alloc_size64_field;
			ft = ExtentType::ft_int64;
		}
	}
	
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
		((Variable32Field *)field)->set(value);
		break;

	case ExtentType::ft_fixedwidth:
		//		((FixedWidthField *)field)->set(value,2);
		assert(0);
		break;

	default:
		assert(0);
	}
}
