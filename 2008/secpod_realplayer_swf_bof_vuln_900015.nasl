# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900015");
  script_version("2022-07-06T10:11:12+0000");
  script_tag(name:"last_modification", value:"2022-07-06 10:11:12 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2007-5400");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Buffer overflow");
  script_name("RealPlayer SWF Frame Handling Buffer Overflow Vulnerability (Windows)");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/07252008_player/en/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30370");
  script_xref(name:"URL", value:"http://secunia.com/advisories/27620/");

  script_tag(name:"summary", value:"RealPlayer is prone to a buffer overflow vulnerability.");

  script_tag(name:"insight", value:"The flaw exists due to a design error in handling/parsing of frames
  in Shockwave Flash (SWF) files.");

  script_tag(name:"affected", value:"RealPlayer Version 10, 10.5 and 11 on Windows (All).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version available.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to
  execute arbitrary code on a user's system.");

  exit(0);
}

 include("smb_nt.inc");
 include("secpod_smb_func.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 realPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                        "\App Paths\realplay.exe", item:"Path");
 if(!realPath){
    exit(0);
 }

 realExe = realPath + "\realplay.exe";

 v = GetVersionFromFile(file:realExe, verstr:"ProductVersion", offset:-90000);

 # RealPlayer version <= 10 (6.0.12.1040-6.0.12.1663, 6.0.12.1675, 6.0.12.1698,
 # and 6.0.12.1741)
 if(ereg(pattern:"^([0-5]\..*|6\.0\.([0-9]\..*|1?[01]\..*|12\.(10[4-9]?[0-9]?" +
         "|1[1-5][0-9][0-9]|16[0-5][0-9]|166[0-3]|1675|1698|1741)|" +
         "14\.(73[89]|7[4-9][0-9]|80[0-2]|806)))$",
     string:v)){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
 }
