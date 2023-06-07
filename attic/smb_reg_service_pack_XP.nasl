###############################################################################
# OpenVAS Vulnerability Test
#
# SMB Registry : XP Service Pack version
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2005 Alert4Web.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.11119");
  script_version("2022-04-13T07:21:45+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11202");
  script_cve_id("CVE-1999-0662");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SMB Registry : XP Service Pack version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Alert4Web.com");
  script_family("Windows");

  script_tag(name:"summary", value:"This script reads the registry key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
  to determine the Service Pack the host is running.

  This VT has been replaced by 'Microsoft Windows Service Pack Missing Multiple Vulnerabilities' (OID: 1.3.6.1.4.1.25623.1.0.902909).");

  script_tag(name:"insight", value:"By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
  it was possible to determine that the remote Windows XP system is not up to date.");

  script_tag(name:"solution", value:"Apply Windows XP Service Pack 2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
