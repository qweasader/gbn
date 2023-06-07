###############################################################################
# OpenVAS Vulnerability Test
#
# TeamSpeak Client Arbitrary command execution vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801537");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_name("TeamSpeak Client Arbitrary command execution vulnerability (Windows)");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Oct/439");
  script_xref(name:"URL", value:"http://www.nsense.fi/advisories/nsense_2010_002.txt");
  script_xref(name:"URL", value:"http://archives.free.net.ph/message/20101028.062014.2328daac.ja.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"insight", value:"The specific flaw exists within the 'TeamSpeak.exe' module, teardown procedure
  responsible for freeing dynamically allocated application handles.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the Teamspeak 3 or later");

  script_tag(name:"summary", value:"TeamSpeak client is prone to an arbitrary command execution vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code in
  the context of the user running the application.");

  script_tag(name:"affected", value:"Teamspeak 2 version 2.0.32.60");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  tsName = registry_get_sz(key:key + item, item:"DisplayName");
  if("TeamSpeak 2" >< tsName)
  {
    tsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(tsVer != NULL)
    {
      if(version_is_less_equal(version:tsVer, test_version:"2.0.32.60"))
      {
        report = report_fixed_ver(installed_version:tsVer, vulnerable_range:"Less or equal to 2.0.32.60");
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
}
