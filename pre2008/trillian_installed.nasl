###############################################################################
# OpenVAS Vulnerability Test
#
# Trillian is installed
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11428");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5677");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5733");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5775");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5776");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5783");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Trillian is installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"The remote host is using Trillian - a p2p software,
  which may not be suitable for a business environment.");

  script_tag(name:"solution", value:"Uninstall this software");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if( ! registry_key_exists( key:key ) ) exit( 0 );

foreach item( registry_enum_keys( key:key ) ) {
  name = registry_get_sz( key:key + item, item:"DisplayName" );
  if( name == "Trillian" ) {
    security_message( port:0 );
    exit( 0 );
  }
}

exit( 99 );
