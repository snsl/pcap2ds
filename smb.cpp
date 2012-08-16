/* smb.cpp
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

#include<protocol.hpp>
#include<smb.hpp>

using namespace std;

Int64Field * smb::current_offset_field;
Int64Field * smb::alloc_size64_field;

const string smb::smb_xml(
  "<ExtentType namespace=\"snsl.engr.uconn.edu\" name=\"Trace::SMB::SNSL\" version=\"1.0\" pack_null_compact=\"non_bool\"\n"
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
  "  <field type=\"variable32\" name=\"path\" print_format=\"%s\"/>\n"
  "  <field type=\"int32\" name=\"timeout\" />\n"
  "  <field type=\"int64\" name=\"alloc_size64\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"alloc_size\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.encrypted\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.not_content_indexed\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.offline\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.compressed\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.reparse\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.sparse\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.temporary\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.normal\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.device\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.directory\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.volume\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.system\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.hidden\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.read_only\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file_attribute.archive\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.generic_read\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.generic_write\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.generic_execute\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.generic_all\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.maximum_allowed\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.system_security\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.synchronize\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.write_owner\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.write_dac\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.read_control\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.delete\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.write_attributes\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.read_attributes\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.delete_child\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.execute\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.write_ea\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.read_ea\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.append\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.write\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.read\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"access.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.writethrough\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"access.caching\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"access.locality\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"access.sharing\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"access.mode\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create.ext\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create.dir\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create.batch_oplock\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create.oplock\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"share.access.delete\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"share.access.write\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"share.access.read\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.directory\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.write_through\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.sequential_only\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.intermediate_buffering\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.sync_io_alert\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.sync_io_nonalert\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.non_directory\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.create_tree_connection\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.complete_if_oplocked\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.no_ea_knowledge\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.eight_dot_three_only\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.random_access\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.delete_on_close\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.open_by_fileid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.backup_intent\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.no_compression\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.reserve_opfilter\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.open_reparse_point\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.open_no_recall\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.create_options.open_for_free_space_query\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"nt.function\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"create_options\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"create.disposition\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"current_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"offset_high\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"rfid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"pwlen\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"password\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"connect.flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"service\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"andxoffset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"connect.support\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"andx.maximal_access_rights\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"andx.guest_access_rights\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"impersonation_level\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"security.flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"remaining\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"data_len_high\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"data_len_low\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"data_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"data_offset32\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"data_disp\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"dialect.name\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"close.fid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"write.mode.write_through\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"dcm\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"link_count\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"maxcount_low\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"mincount\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"maxcount_high\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"transaction.flags.owt\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"transaction.flags.dtid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"trans.name\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"tpc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"tdc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"mpc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"mdc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"msc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"pc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"po\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"dc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"sc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"is_directory\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"delete_pending\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"pd\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"trans2.cmd\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"file\" opt_nullable=\"yes\" print_format=\"%s\"/>\n"
  "  <field type=\"int32\" name=\"trans2.flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"qpi_loi\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"trans2.qpi.file\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"ea.error_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"create.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"change.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"last_write.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"end_of_file\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"change_time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"share_access\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"connect.flags.dtid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"connect.flags.extendedresp\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"connect.flags.extendedsig\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"connect.support.cscmask\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"connect.support.dfs\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"connect.support.extendedsig\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"connect.support.search\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"connect.support.uniqfilename\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"create.action\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"create.file_id_64b\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"ea.list_length\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"end_of_search\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"error_class\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"error_code\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"ff2_loi\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"file_index\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"file_name_len\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"file_type\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.backup\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.close\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.continue\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.eos\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"find_first2.flags.resume\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"free_alloc_units\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.cpn\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.css\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.fc\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.ns\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.pacls\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.rov\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.se\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.sla\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.soids\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.srp\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.srs\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.ssf\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.uod\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.vis\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"fs_attr.vq\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fs_bytes_per_sector\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fs_max_name_len\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fs_name.len\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"fs_name\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fs_sector_per_unit\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"impersonation.level\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"index_number\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"ipc_state.endpoint\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"ipc_state.icount\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"ipc_state.nonblocking\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"ipc_state.pipe_type\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"ipc_state.read_mode\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"last_name_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"lock.type.cancel\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"lock.type.change\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"lock.type.large\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"lock.type.oplock_release\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"lock.type.shared\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"locking.num_locks\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"locking.num_unlocks\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"locking.oplock.level\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"next_entry_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.attributes\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.creation\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.dir_name\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.ea\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.file_name\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.last_access\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.last_write\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.security\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.stream_name\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.stream_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.notify.stream_write\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"nt.notify.watch_tree\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"oplock.level\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"qfsi_loi\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.archive\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.directory\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.hidden\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.read_only\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.system\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"search.attribute.volume\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"search_count\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"search_id\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"search_pattern\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"security.flags.context_tracking\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"security.flags.effective_only\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"short_file\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"short_file_name_len\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"spi_loi\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"storage_type\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"trans_name\" opt_nullable=\"yes\" />\n"
  "  <field type=\"fixedwidth\" name=\"volume_guid\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"bool\" name=\"write.mode.message_start\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"write.mode.raw\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"write.mode.return_remaining\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"pipe.function\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"pipe.priority\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"buffer_format\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"dir_name\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"old_file\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"file_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"server_fid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"open.flags.add_info\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"open.flags.ex_oplock\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"open.flags.batch_oplock\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"open.function.create\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"open.function.open\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"open.action.lock\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"open.action.open\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"volume.serial\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"volume.label.len\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"volume.label\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt_qsd.owner\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt_qsd.group\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt_qsd.dacl\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt_qsd.sacl\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"sec_desc_len\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file.accessmask.write_attribute\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file.accessmask.read_attribute\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file.accessmask.execute\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file.accessmask.write_ea\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file.accessmask.read_ea\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file.accessmask.append_data\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file.accessmask.write_data\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"file.accessmask.read_data\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"disposition.delete_on_close\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"cancel_to\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"max_referral_level\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"nt.ioctl.isfsctl\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"nt.ioctl.flags.root_handle\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"nt.notify.action\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fs_id\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"fs_units\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"avail.units\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.cmd\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function.device\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function.access\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function.function\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function.method\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.ioctl.is_fsctl\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.max_ioctl_in_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.max_ioctl_out_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.object_id\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.birth_volume_id\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.birth_object_id\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.domain_id\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"int64\" name=\"smb2.eof\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.allocation_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.close.flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.close.pq_attrib\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.buffer_code.dynamic\" />\n"
  "  <field type=\"int32\" name=\"smb2.buffer_code.length\" />\n"
  "  <field type=\"int64\" name=\"smb2.signature\" />\n"
  "  <field type=\"variable32\" name=\"smb2.tag\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.sesid\" />\n"
  "  <field type=\"int64\" name=\"smb2.aid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.tid\" />\n"
  "  <field type=\"int32\" name=\"smb2.pid\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.fid\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"int64\" name=\"smb2.qfid_fid\" opt_nullable=\"yes\" />\n"
//  "  <field type=\"int64\" name=\"smb2.seq_num\" />\n"	// Causes crash of pcap2ds
  "  <field type=\"int32\" name=\"smb2.chain_offset\" />\n"
  "  <field type=\"bool\" name=\"smb2.flags.dfs\" />\n"
  "  <field type=\"bool\" name=\"smb2.flags.signature\" />\n"
  "  <field type=\"bool\" name=\"smb2.flags.chained\" />\n"
  "  <field type=\"bool\" name=\"smb2.flags.async\" />\n"
  "  <field type=\"bool\" name=\"smb2.flags.response\" />\n"
  "  <field type=\"int32\" name=\"smb2.dialect\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.dialect_count\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.credit.charge\" />\n"
  "  <field type=\"int32\" name=\"smb2.credits.granted\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.credits.requested\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.nt_status\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.header_len\" />\n"
  "  <field type=\"int32\" name=\"smb2.channel\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.channel_sequence\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.channel_info_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.channel_info_length\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.tcon_frame\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"variable32\" name=\"smb2.tree\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"smb2.share_type\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.mxac_status\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.write.remaining\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.write.count\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.write.flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.write.flags.write_through\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.write_data\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.write_length\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.error.reserved\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.error.byte_count\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.error.data\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.olb.offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.olb.length\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"smb2.file_info.infolevel\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"smb2.class\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.max_response_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.max_trans_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.max_read_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.max_write_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.required_size\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.remaining_bytes\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.file_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.find.info_blob\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.security_blob\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.previous_sesid\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.dhnq_buffer_reserved\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"smb2.create.oplock\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"smb2.create.rep_flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.create.rep_flags.reparse_point\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.create.action\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.create.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.create.chain_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.current_time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.boot_time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.lease.lease_key\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"int64\" name=\"smb2.lease.lease_duration\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.lease.lease_flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.lease.lease_state\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.lease.lease_state.read_caching\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.lease.lease_state.handle_caching\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.lease.lease_state.write_caching\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.lease.lease_state.break_ack_required\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.lease.lease_state.break_in_progress\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.lease.lease_state.parent_lease_key_set\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.last_access.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.last_write.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.last_change.time\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.data_offset\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.read_length\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.read_remaining\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int64\" name=\"smb2.read_data\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.share.caching\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.share_caps\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_caps.dfs\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_caps.continuous_availability\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.share_flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.dfs\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.dfs_root\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.restrict_exclusive_opens\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.force_shared_delete\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.allow_namespace_caching\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.access_based_dir_enum\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.force_levelii_oplock\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.enable_hash_v1\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.enable_hash_v2\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.share_flags.encrypt_data\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.session_flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.ses_flags.null\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.ses_flags.guest\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.capabilities\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.capabilities.dfs\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.capabilities.leasing\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.capabilities.large_mtu\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.capabilities.multi_channel\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.capabilities.persistent_handles\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.capabilities.directory_leasing\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.capabilities.encryption\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"smb2.ses_req_flags\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.ses_req_flags.session_binding\" opt_nullable=\"yes\" />\n"
  "  <field type=\"byte\" name=\"smb2.sec_mode\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.sec_mode.sign_required\" opt_nullable=\"yes\" />\n"
  "  <field type=\"bool\" name=\"smb2.sec_mode.sign_enabled\" opt_nullable=\"yes\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.server_guid\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.client_guid\" opt_nullable=\"yes\" size=\"16\" />\n"
  "</ExtentType>\n"
  );

bool smb::handle_smb_exception(const gchar *extentName,
				 const header_field_info *hfinfo,
				 ExtentSeries &series,
				 FieldMap &map)
{
	if (strcmp(extentName,"offset") == 0) {
		if (hfinfo->type == FT_UINT64) {
			current_offset_field =
				new Int64Field(series, "current_offset",
						   Field::flag_nullable);
			return true;
		}
	} else if (strcmp(extentName,"alloc_size") == 0) {
		if (hfinfo->type == FT_UINT64) {
			alloc_size64_field =
				new Int64Field(series, "alloc_size64",
						   Field::flag_nullable);
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
smb::init(ExtentTypeLibrary& library, ExtentSeries& series)
{
	const ExtentType::Ptr type = library.registerTypePtr(smb_xml);
	series.setType(type);

	add_proto_fields("smb", 4, epan2dstype, series, type, handle_smb_exception);
	add_proto_fields("pipe", 0, epan2dstype, series, type, NULL);
	add_proto_fields("smb2", 0, epan2dstype, series, type, NULL);

	ignored_fields.insert("smb2.seq_num");
	ignored_fields.insert("smb.reserved");
	ignored_fields.insert("smb.padding");
	ignored_fields.insert("smb.unknown_data");
	ignored_fields.insert("smb.response_to");
	ignored_fields.insert("smb.file_data");
	ignored_fields.insert("smb2.unknown");
	ignored_fields.insert("smb2.response_to");
	ignored_fields.insert("smb2.reserved");

	ignored_fields.insert("nt.sec_desc.revision");
	ignored_fields.insert("nt.sec_desc.type.self_relative");
	ignored_fields.insert("nt.sec_desc.type.rm_control_valid");
	ignored_fields.insert("nt.sec_desc.type.sacl_protected");
	ignored_fields.insert("nt.sec_desc.type.dacl_protected");
	ignored_fields.insert("nt.sec_desc.type.sacl_auto_inherited");
	ignored_fields.insert("nt.sec_desc.type.dacl_auto_inherited");
	ignored_fields.insert("nt.sec_desc.type.sacl_auto_inherit_req");
	ignored_fields.insert("nt.sec_desc.type.dacl_auto_inherit_req");
	ignored_fields.insert("nt.sec_desc.type.server_security");
	ignored_fields.insert("nt.sec_desc.type.dacl_trusted");
	ignored_fields.insert("nt.sec_desc.type.sacl_defaulted");
	ignored_fields.insert("nt.sec_desc.type.sacl_present");
	ignored_fields.insert("nt.sec_desc.type.dacl_defaulted");
	ignored_fields.insert("nt.sec_desc.type.dacl_present");
	ignored_fields.insert("nt.sec_desc.type.group_defaulted");
	ignored_fields.insert("nt.sec_desc.type.owner_defaulted");
	ignored_fields.insert("nt.acl.revision");
	ignored_fields.insert("nt.acl.size");
	ignored_fields.insert("nt.acl.num_aces");
	ignored_fields.insert("nt.ace.type");
	ignored_fields.insert("nt.ace.flags.failed_access");
	ignored_fields.insert("nt.ace.flags.successful_access");
	ignored_fields.insert("nt.ace.flags.inherited_ace");
	ignored_fields.insert("nt.ace.flags.inherit_only");
	ignored_fields.insert("nt.ace.flags.non_propagate_inherit");
	ignored_fields.insert("nt.ace.flags.container_inherit");
	ignored_fields.insert("nt.ace.flags.object_inherit");
	ignored_fields.insert("nt.ace.size");
	ignored_fields.insert("nt.access_mask");
	ignored_fields.insert("nt.access_mask.generic_read");
	ignored_fields.insert("nt.access_mask.generic_write");
	ignored_fields.insert("nt.access_mask.generic_execute");
	ignored_fields.insert("nt.access_mask.generic_all");
	ignored_fields.insert("nt.access_mask.maximum_allowed");
	ignored_fields.insert("nt.access_mask.access_sacl");
	ignored_fields.insert("nt.access_mask.synchronise");
	ignored_fields.insert("nt.access_mask.write_owner");
	ignored_fields.insert("nt.access_mask.write_dac");
	ignored_fields.insert("nt.access_mask.read_control");
	ignored_fields.insert("nt.access_mask.delete");
	ignored_fields.insert("nt.sid");
	ignored_fields.insert("nt.sid.revision");
	ignored_fields.insert("nt.sid.num_auth");
	ignored_fields.insert("nt.sid.auth");
	ignored_fields.insert("nt.sid.subauth");
	ignored_fields.insert("nt.sid.rid");
	ignored_fields.insert("nt.sid.wkwn");
	ignored_fields.insert("nt.sid.domain");

	ignored_fields.insert("udp.checksum");
	ignored_fields.insert("udp.checksum_good");
	ignored_fields.insert("udp.checksum_bad");
	ignored_fields.insert("udp.checksum_coverage");
	ignored_fields.insert("udp.length");
	ignored_fields.insert("udp.port");
	ignored_fields.insert("udp.dstport");
	ignored_fields.insert("udp.srcport");
	ignored_fields.insert("http.accept");
	ignored_fields.insert("http.user_agent");
	ignored_fields.insert("http.request");
	ignored_fields.insert("http.request.full_uri");
	ignored_fields.insert("http.request.uri");
	ignored_fields.insert("http.request.method");
	ignored_fields.insert("http.request.version");
	ignored_fields.insert("http.response");
	ignored_fields.insert("http.response.phrase");
	ignored_fields.insert("http.response.code");
	ignored_fields.insert("http.server");
	ignored_fields.insert("http.cache_control");
	ignored_fields.insert("http.location");
	ignored_fields.insert("http.host");
	ignored_fields.insert("http.connection");
	ignored_fields.insert("http.accept_encoding");
	ignored_fields.insert("http.content_length");
	ignored_fields.insert("http.content_length_header");
	ignored_fields.insert("http.date");
	ignored_fields.insert("http.content_type");
	ignored_fields.insert("http.notification");
	ignored_fields.insert("expert.group");
	ignored_fields.insert("expert.severity");
	ignored_fields.insert("expert.message");
	ignored_fields.insert("ipv6.host");
	ignored_fields.insert("ipv6.dst_host");
	ignored_fields.insert("ipv6.addr");
	ignored_fields.insert("ipv6.dst");
	ignored_fields.insert("ipv6.host");
	ignored_fields.insert("ipv6.src");
	ignored_fields.insert("ipv6.src_host");
	ignored_fields.insert("ipv6.hlim");
	ignored_fields.insert("ipv6.nxt");
	ignored_fields.insert("ipv6.plen");
	ignored_fields.insert("ipv6.flow");
	ignored_fields.insert("ipv6.traffic_class.ce");
	ignored_fields.insert("ipv6.traffic_class.ect");
	ignored_fields.insert("ipv6.traffic_class.dscp");
	ignored_fields.insert("ipv6.class");
	ignored_fields.insert("ipv6.version");
	ignored_fields.insert("icmpv6.opt.type");
	ignored_fields.insert("icmpv6.opt.length");
	ignored_fields.insert("icmpv6.opt.linkaddr");
	ignored_fields.insert("icmpv6.opt.target_linkaddr");
	ignored_fields.insert("icmpv6.opt.src_linkaddr");
	ignored_fields.insert("icmpv6.nd.na.flag");
	ignored_fields.insert("icmpv6.nd.na.flag.r");
	ignored_fields.insert("icmpv6.nd.na.flag.s");
	ignored_fields.insert("icmpv6.nd.na.flag.o");
	ignored_fields.insert("icmpv6.nd.na.flag.rsv");
	ignored_fields.insert("icmpv6.nd.na.target_address");
	ignored_fields.insert("icmpv6.nd.ns.target_address");
	ignored_fields.insert("icmpv6.checksum");
	ignored_fields.insert("icmpv6.code");
	ignored_fields.insert("icmpv6.type");
	ignored_fields.insert("icmpv6.reserved");
	ignored_fields.insert("arp.opcode");
	ignored_fields.insert("arp.hw.size");
	ignored_fields.insert("arp.hw.type");
	ignored_fields.insert("arp.proto.type");
	ignored_fields.insert("arp.proto.size");
	ignored_fields.insert("arp.src.hw_mac");
	ignored_fields.insert("arp.src.proto_ipv4");
	ignored_fields.insert("arp.dst.hw_mac");
	ignored_fields.insert("arp.dst.proto_ipv4");
	ignored_fields.insert("ssl.app_data");
	ignored_fields.insert("ssl.handshake.ciphersuite");
	ignored_fields.insert("ssl.handshake.cipher_suites_length");
	ignored_fields.insert("ssl.handshake.comp_methods_length");
	ignored_fields.insert("ssl.handshake.comp_method");
	ignored_fields.insert("ssl.handshake.extensions_length");
	ignored_fields.insert("ssl.handshake.extensions_server_name_list_len");
	ignored_fields.insert("ssl.handshake.extensions_server_name_type");
	ignored_fields.insert("ssl.handshake.extensions_server_name_len");
	ignored_fields.insert("ssl.handshake.extensions_server_name");
	ignored_fields.insert("ssl.handshake.extensions_elliptic_curves_length");
	ignored_fields.insert("ssl.handshake.extensions_elliptic_curve");
	ignored_fields.insert("ssl.handshake.extensions_ec_point_formats_length");
	ignored_fields.insert("ssl.handshake.extensions_ec_point_format");
	ignored_fields.insert("ssl.handshake.extensions_npn");
	ignored_fields.insert("ssl.handshake.extensions_npn_str_len");
	ignored_fields.insert("ssl.handshake.extensions_reneg_info_len");
	ignored_fields.insert("ssl.handshake.extension.type");
	ignored_fields.insert("ssl.handshake.extension.len");
	ignored_fields.insert("ssl.handshake.extension.data");
	ignored_fields.insert("ssl.handshake.type");
	ignored_fields.insert("ssl.handshake.length");
	ignored_fields.insert("ssl.handshake.version");
	ignored_fields.insert("ssl.handshake.random_time");
	ignored_fields.insert("ssl.handshake.random_bytes");
	ignored_fields.insert("ssl.handshake.session_id_length");
	ignored_fields.insert("ssl.handshake.session_id");
	ignored_fields.insert("ssl.record.length");
	ignored_fields.insert("ssl.record.version");
	ignored_fields.insert("ssl.record.content_type");
	ignored_fields.insert("nbns.id");
	ignored_fields.insert("nbns.flags");
	ignored_fields.insert("nbns.flags.response");
	ignored_fields.insert("nbns.flags.opcode");
	ignored_fields.insert("nbns.flags.truncated");
	ignored_fields.insert("nbns.flags.recdesired");
	ignored_fields.insert("nbns.flags.broadcast");
	ignored_fields.insert("nbns.flags.authoritative");
	ignored_fields.insert("nbns.flags.recavail");
	ignored_fields.insert("nbns.flags.rcode");
	ignored_fields.insert("nbns.count.queries");
	ignored_fields.insert("nbns.count.answers");
	ignored_fields.insert("nbns.count.auth_rr");
	ignored_fields.insert("nbns.count.add_rr");
	ignored_fields.insert("nbdgm.type");
	ignored_fields.insert("nbdgm.next");
	ignored_fields.insert("nbdgm.first");
	ignored_fields.insert("nbdgm.node_type");
	ignored_fields.insert("nbdgm.dgram_id");
	ignored_fields.insert("nbdgm.src.ip");
	ignored_fields.insert("nbdgm.src.port");
	ignored_fields.insert("mailslot.opcode");
	ignored_fields.insert("mailslot.priority");
	ignored_fields.insert("mailslot.class");
	ignored_fields.insert("mailslot.size");
	ignored_fields.insert("mailslot.name");
	ignored_fields.insert("macc.opcode");
	ignored_fields.insert("macc.pause_time");
	ignored_fields.insert("db-lsp.text");
	ignored_fields.insert("browser.command");
	ignored_fields.insert("browser.update_count");
	ignored_fields.insert("browser.period");
	ignored_fields.insert("browser.server");
	ignored_fields.insert("browser.os_major");
	ignored_fields.insert("browser.os_minor");
	ignored_fields.insert("browser.server_type");
	ignored_fields.insert("browser.server_type.workstation");
	ignored_fields.insert("browser.server_type.server");
	ignored_fields.insert("browser.server_type.sql");
	ignored_fields.insert("browser.server_type.domain_controller");
	ignored_fields.insert("browser.server_type.backup_controller");
	ignored_fields.insert("browser.server_type.time");
	ignored_fields.insert("browser.server_type.apple");
	ignored_fields.insert("browser.server_type.novell");
	ignored_fields.insert("browser.server_type.member");
	ignored_fields.insert("browser.server_type.print");
	ignored_fields.insert("browser.server_type.dialin");
	ignored_fields.insert("browser.server_type.xenix");
	ignored_fields.insert("browser.server_type.ntw");
	ignored_fields.insert("browser.server_type.wfw");
	ignored_fields.insert("browser.server_type.nts");
	ignored_fields.insert("browser.server_type.browser.potential");
	ignored_fields.insert("browser.server_type.browser.backup");
	ignored_fields.insert("browser.server_type.browser.master");
	ignored_fields.insert("browser.server_type.browser.domain_master");
	ignored_fields.insert("browser.server_type.osf");
	ignored_fields.insert("browser.server_type.vms");
	ignored_fields.insert("browser.server_type.w95");
	ignored_fields.insert("browser.server_type.dfs");
	ignored_fields.insert("browser.server_type.local");
	ignored_fields.insert("browser.server_type.domainenum");
	ignored_fields.insert("browser.proto_major");
	ignored_fields.insert("browser.proto_minor");
	ignored_fields.insert("browser.sig");
	ignored_fields.insert("browser.comment");
	ignored_fields.insert("dns.response_to");
	ignored_fields.insert("dns.time");
	ignored_fields.insert("dns.id");
	ignored_fields.insert("dns.flags");
	ignored_fields.insert("dns.flags.response");
	ignored_fields.insert("dns.flags.opcode");
	ignored_fields.insert("dns.flags.authoritative");
	ignored_fields.insert("dns.flags.truncated");
	ignored_fields.insert("dns.flags.recdesired");
	ignored_fields.insert("dns.flags.recavail");
	ignored_fields.insert("dns.flags.z");
	ignored_fields.insert("dns.flags.authenticated");
	ignored_fields.insert("dns.flags.checkdisable");
	ignored_fields.insert("dns.flags.rcode");
	ignored_fields.insert("dns.flags.conflict");
	ignored_fields.insert("dns.flags.tentative");
	ignored_fields.insert("dns.count.queries");
	ignored_fields.insert("dns.count.answers");
	ignored_fields.insert("dns.count.auth_rr");
	ignored_fields.insert("dns.count.add_rr");
	ignored_fields.insert("dns.qry.name");
	ignored_fields.insert("dns.qry.type");
	ignored_fields.insert("dns.qry.class");
	ignored_fields.insert("dns.resp.name");
	ignored_fields.insert("dns.resp.type");
	ignored_fields.insert("dns.resp.class");
	ignored_fields.insert("dns.resp.ttl");
	ignored_fields.insert("dns.resp.len");
	ignored_fields.insert("dns.resp.primaryname");
	ignored_fields.insert("dns.resp.addr");
	ignored_fields.insert("dcerpc.nt.open_frame");
	ignored_fields.insert("dcerpc.nt.close_frame");
	ignored_fields.insert("gss-api.OID");
	ignored_fields.insert("spnego.negResult");
	ignored_fields.insert("spnego.MechType");
	ignored_fields.insert("spnego.mechType");
	ignored_fields.insert("spnego.mechTypes");
	ignored_fields.insert("spnego.mechToken");
	ignored_fields.insert("spnego.mechListMIC");
	ignored_fields.insert("spnego.supportedMech");
	ignored_fields.insert("spnego.principal");
	ignored_fields.insert("spnego.responseToken");
	ignored_fields.insert("ntlmssp.identifier");
	ignored_fields.insert("ntlmssp.messagetype");
	ignored_fields.insert("ntlmssp.authenticate.mic");
	ignored_fields.insert("ntlmssp.reserved");
	ignored_fields.insert("ntlmssp.requestnonntsession");
	ignored_fields.insert("ntlmssp.requesttarget");
	ignored_fields.insert("ntlmssp.targettypeshare");
	ignored_fields.insert("ntlmssp.targettypeserver");
	ignored_fields.insert("ntlmssp.targettypedomain");
	ignored_fields.insert("ntlmssp.version.ntlm_current_revision");
	ignored_fields.insert("ntlmssp.version.build_number");
	ignored_fields.insert("ntlmssp.version.major");
	ignored_fields.insert("ntlmssp.version.minor");
	ignored_fields.insert("ntlmssp.negotiateunicode");
	ignored_fields.insert("ntlmssp.negotiateoem");
	ignored_fields.insert("ntlmssp.negotiate00000008");
	ignored_fields.insert("ntlmssp.negotiate00000100");
	ignored_fields.insert("ntlmssp.negotiate00000800");
	ignored_fields.insert("ntlmssp.negotiate00004000");
	ignored_fields.insert("ntlmssp.negotiate04000000");
	ignored_fields.insert("ntlmssp.negotiate08000000");
	ignored_fields.insert("ntlmssp.negotiate10000000");
	ignored_fields.insert("ntlmssp.negotiatent00200000");
	ignored_fields.insert("ntlmssp.negotiatent01000000");
	ignored_fields.insert("ntlmssp.negotiatent04000000");
	ignored_fields.insert("ntlmssp.negotiatent08000000");
	ignored_fields.insert("ntlmssp.negotiatent10000000");
	ignored_fields.insert("ntlmssp.negotiatesign");
	ignored_fields.insert("ntlmssp.negotiateseal");
	ignored_fields.insert("ntlmssp.negotiatedatagram");
	ignored_fields.insert("ntlmssp.negotiatelmkey");
	ignored_fields.insert("ntlmssp.negotiatentlm");
	ignored_fields.insert("ntlmssp.negotiatentlm2");
	ignored_fields.insert("ntlmssp.negotiatentonly");
	ignored_fields.insert("ntlmssp.negotiateoemdomainsupplied");
	ignored_fields.insert("ntlmssp.negotiateoemworkstationsupplied");
	ignored_fields.insert("ntlmssp.negotiatealwayssign");
	ignored_fields.insert("ntlmssp.negotiateidentify");
	ignored_fields.insert("ntlmssp.negotiateversion");
	ignored_fields.insert("ntlmssp.negotiatetargetinfo");
	ignored_fields.insert("ntlmssp.negotiate56");
	ignored_fields.insert("ntlmssp.negotiate128");
	ignored_fields.insert("ntlmssp.negotiatekeyexch");
	ignored_fields.insert("ntlmssp.negotiateflags");
	ignored_fields.insert("ntlmssp.negotiate.domain");
	ignored_fields.insert("ntlmssp.negotiate.callingworkstation");
	ignored_fields.insert("ntlmssp.blob.length");
	ignored_fields.insert("ntlmssp.blob.maxlen");
	ignored_fields.insert("ntlmssp.blob.offset");
	ignored_fields.insert("ntlmssp.string.length");
	ignored_fields.insert("ntlmssp.string.maxlen");
	ignored_fields.insert("ntlmssp.string.offset");
	ignored_fields.insert("ntlmssp.auth.domain");
	ignored_fields.insert("ntlmssp.auth.username");
	ignored_fields.insert("ntlmssp.auth.hostname");
	ignored_fields.insert("ntlmssp.auth.sesskey");
	ignored_fields.insert("ntlmssp.auth.ntresponse");
	ignored_fields.insert("ntlmssp.auth.lmresponse");
	ignored_fields.insert("ntlmssp.ntlmclientchallenge");
	ignored_fields.insert("ntlmssp.ntlmserverchallenge");
	ignored_fields.insert("ntlmssp.challenge.target_name");
	ignored_fields.insert("ntlmssp.challenge.target_info.length");
	ignored_fields.insert("ntlmssp.challenge.target_info.maxlen");
	ignored_fields.insert("ntlmssp.challenge.target_info.offset");
	ignored_fields.insert("ntlmssp.challenge.target_info.item.type");
	ignored_fields.insert("ntlmssp.challenge.target_info.item.length");
	ignored_fields.insert("ntlmssp.challenge.target_info.nb_domain_name");
	ignored_fields.insert("ntlmssp.challenge.target_info.nb_computer_name");
	ignored_fields.insert("ntlmssp.challenge.target_info.dns_domain_name");
	ignored_fields.insert("ntlmssp.challenge.target_info.dns_computer_name");
	ignored_fields.insert("ntlmssp.challenge.target_info.dns_tree_name");
	ignored_fields.insert("ntlmssp.challenge.target_info.timestamp");
	ignored_fields.insert("ntlmssp.ntlmv2_response");
	ignored_fields.insert("ntlmssp.ntlmv2_response.hmac");
	ignored_fields.insert("ntlmssp.ntlmv2_response.header");
	ignored_fields.insert("ntlmssp.ntlmv2_response.reserved");
	ignored_fields.insert("ntlmssp.ntlmv2_response.time");
	ignored_fields.insert("ntlmssp.ntlmv2_response.chal");
	ignored_fields.insert("ntlmssp.ntlmv2_response.unknown");
	ignored_fields.insert("ntlmssp.ntlmv2_response.item.type");
	ignored_fields.insert("ntlmssp.ntlmv2_response.item.length");
	ignored_fields.insert("ntlmssp.ntlmv2_response.nb_domain_name");
	ignored_fields.insert("ntlmssp.ntlmv2_response.nb_computer_name");
	ignored_fields.insert("ntlmssp.ntlmv2_response.dns_domain_name");
	ignored_fields.insert("ntlmssp.ntlmv2_response.dns_computer_name");
	ignored_fields.insert("ntlmssp.ntlmv2_response.dns_tree_name");
	ignored_fields.insert("ntlmssp.ntlmv2_response.timestamp");
	ignored_fields.insert("ntlmssp.ntlmv2_response.flags");
	ignored_fields.insert("ntlmssp.ntlmv2_response.restrictions");
	ignored_fields.insert("ntlmssp.ntlmv2_response.channel_bindings");
	ignored_fields.insert("ntlmssp.ntlmv2_response.target_name");

	return type;
}

void smb::finish()
{
	FieldMap::iterator i;
	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
		ExtentTypeFieldInfo &etfi = (*i).second;
		delete etfi.field;
	}

	delete current_offset_field;
	delete alloc_size64_field;
}

void smb::packet_start(ExtentType::Ptr type)
{
	/* set all the nullable fields to null */
	FieldMap::iterator i;
	for (i=epan2dstype.begin(); i!=epan2dstype.end(); i++) {
		ExtentTypeFieldInfo &etfi = (*i).second;
		if (etfi.nullable) {
			etfi.field->setNull();
		}
	}
	current_offset_field->setNull();
	alloc_size64_field->setNull();
}

void smb::parse(field_info *fi)
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
