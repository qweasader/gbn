###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows TrueType Font Parsing Privilege Elevation Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802500");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2011-3402");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-07 16:44:35 +0530 (Mon, 07 Nov 2011)");
  script_name("Microsoft Windows TrueType Font Parsing Privilege Elevation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2639658");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50462");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2011/2639658");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code with
  kernel-level privileges. Failed exploit attempts may result in a denial-of-service condition.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior

  - Microsoft Windows server 2003 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to due to an error within the Win32k kernel-mode
  driver when parsing TrueType fonts.");

  script_tag(name:"solution", value:"Apply the workaround.");

  script_tag(name:"summary", value:"Microsoft Windows operating system is prone to a pivilege escalation vulnerability.

  This VT has been replaced by OID:1.3.6.1.4.1.25623.1.0.902767.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); ## This VT is deprecated as addressed in secpod_ms11-087.nasl