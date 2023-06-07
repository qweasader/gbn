# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# @brief Function that reads the content of given file
#
# @param share  Windows IPC Share
# @param file   File path to read the content
# @param offset Position from which to start the file read
#
# @return The content of the file or FALSE if no connection to the remote
#         system could be opened or the file isn't readable.
#
function GSHB_read_file(share, file, offset) {

  local_var share, file, offset;
  local_var port, soc, name, r, prot, domain, login, pass, uid, tid, fid, size, content;

  port = kb_smb_transport();
  if(!port)
    port = 445;

  soc = open_sock_tcp(port);
  if(!soc)
    return FALSE;

  name = kb_smb_name();
  domain = kb_smb_domain();
  login = kb_smb_login();
  pass = kb_smb_password();

  info = smb_login_and_get_tid_uid(soc:soc, name:name, login:login, passwd:pass, domain:domain, share:share);

  if(isnull(info)) {
    close(soc);
    return FALSE;
  }

  uid = info["uid"];
  tid = info["tid"];

  fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
  if(!fid) {
    close(soc);
    return FALSE;
  }

  size = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
  if(!size) {
    close(soc);
    return FALSE;
  }

  content = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:size, off:offset);
  return content;
}
