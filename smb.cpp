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

const string smb_xml(
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
  "  <field type=\"fixedwidth\" name=\"volume_guid\" opt_nullable=\"yes\" size=\"16\"/>\n"
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
  "  <field type=\"int32\" name=\"smb2.ioctl.function\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function.device\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function.access\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function.function\" opt_nullable=\"yes\" />\n"
  "  <field type=\"int32\" name=\"smb2.ioctl.function.method\" opt_nullable=\"yes\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.object_id\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.birth_volume_id\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.birth_object_id\" opt_nullable=\"yes\" size=\"16\" />\n"
  "  <field type=\"fixedwidth\" name=\"smb2.domain_id\" opt_nullable=\"yes\" size=\"16\" />\n"
  "</ExtentType>\n"
  );

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
			fprintf(stderr, "Field %s does not exist in SMB XML ExtentType Description\n", extentFieldName);
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
smb_init(ExtentTypeLibrary& library, ExtentSeries& series)
{
	const ExtentType::Ptr type = library.registerTypePtr(smb_xml);
	series.setType(type);

	add_proto_fields("smb", 4, epan2dstype, series, type, handle_smb_exception);
	add_proto_fields("pipe", 0, epan2dstype, series, type, NULL);
	add_proto_fields("smb2", 0, epan2dstype, series, type, NULL);

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

void smb_packet_start(ExtentType::Ptr type)
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

void smb_parse(field_info *fi)
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
