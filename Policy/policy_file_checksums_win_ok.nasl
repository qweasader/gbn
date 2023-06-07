###############################################################################
# OpenVAS Vulnerability Test
#
# List Windows File with no checksum violation or error
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96181");
  script_version("2022-06-27T10:12:27+0000");
  script_name("Windows file Checksums: Matches");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:27 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2013-09-09 11:07:49 +0200 (Mon, 09 Sep 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("Policy/policy_file_checksums_win.nasl");
  script_mandatory_keys("policy/file_checksums_win/started");

  script_tag(name:"summary", value:"List Windows files with no checksum violation or error");

  script_tag(name:"qod", value:"98"); # direct authenticated file analysis is pretty reliable

  exit(0);
}

md5pass  = get_kb_list( "policy/file_checksums_win/md5_ok_list" );
sha1pass = get_kb_list( "policy/file_checksums_win/sha1_ok_list" );

if( md5pass || sha1pass ) {

  # Sort to not report changes on delta reports if just the order is different
  if( md5pass )  md5pass  = sort( md5pass );
  if( sha1pass ) sha1pass = sort( sha1pass );

  report  = 'The following file checksums match:\n\n';
  report += 'Filename|Result|Errorcode;\n';

  foreach pass( md5pass ) {
    report += pass + '\n';
  }
  foreach pass( sha1pass ) {
    report += pass + '\n';
  }
  log_message( port:0, data:report );
}

exit( 0 );
