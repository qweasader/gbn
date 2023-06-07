###############################################################################
# OpenVAS Vulnerability Test
#
# Novell iPrint ActiveX control Stack-based BOF Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800070");
  script_version("2022-02-21T14:27:31+0000");
  script_tag(name:"last_modification", value:"2022-02-21 14:27:31 +0000 (Mon, 21 Feb 2022)");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5231");
  script_name("Novell iPrint ActiveX control Stack-based BOF Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary code via a long target
  frame option value, which crashes the browser and may allow code execution.");
  script_tag(name:"affected", value:"Novell iPrint Client version 5.06 and prior on Windows.");
  script_tag(name:"insight", value:"The issue is due to the improper handling of user requests sent to the
  ExecuteRequest method in ienipp.ocx file.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Novell iPrint Client version 5.06 is obsoleted, Upgrade to
  Novell iPrint Client version higher than 5.06.");
  script_tag(name:"summary", value:"Novell iPrint is prone to a stack based buffer overflow vulnerability.");

  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

iPrintVer = registry_get_sz(key:"SOFTWARE\Novell-iPrint",
                            item:"Current Version");
if(!iPrintVer){
  exit(0);
}

novVer = eregmatch(pattern:"v([0-9.]+)", string:iPrintVer);
if(novVer[1] != NULL)
{
  if(version_is_less_equal(version:novVer[1], test_version:"5.06")){
    report = report_fixed_ver(installed_version:novVer[1], vulnerable_range:"Less than or equal to 5.06");
    security_message(port: 0, data: report);
  }
}
