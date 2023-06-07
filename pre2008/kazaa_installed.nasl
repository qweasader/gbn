# OpenVAS Vulnerability Test
# Description: Kazaa is installed
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11426");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 18:10:09 +0200 (Sun, 26 Mar 2006)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4121");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4122");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5317");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6435");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6747");
  script_cve_id("CVE-2002-0314", "CVE-2002-0315");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Kazaa is installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:"Uninstall this software.");

  script_tag(name:"summary", value:"The remote host is using Kazaa - a p2p software, which may not
  be suitable for a business environment.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

rootfile = registry_get_sz(key:"SOFTWARE\Kazaa\CloudLoad", item:"ExeDir");
if(rootfile)
{
 security_message(get_kb_item("SMB/transport"));
}