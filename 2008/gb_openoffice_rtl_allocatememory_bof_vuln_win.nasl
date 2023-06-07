###############################################################################
# OpenVAS Vulnerability Test
#
# OpenOffice rtl_allocateMemory Heap Based BOF Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800009");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-01 17:01:16 +0200 (Wed, 01 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2152");
  script_xref(name:"CB-A", value:"08-0095");
  script_name("OpenOffice rtl_allocateMemory Heap Based BOF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/30599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29622");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2008-2152.html");
  script_xref(name:"URL", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=714");

  script_tag(name:"impact", value:"Exploitation will result in buffer overflows via a specially crafted document
  and allow remote unprivileged user who provides a OpenOffice.org document that
  is opened by a local user to execute arbitrary commands on the system with the
  privileges of the user running OpenOffice.org.");

  script_tag(name:"affected", value:"OpenOffice.org 2.x on Windows (Any).");

  script_tag(name:"insight", value:"The flaw is in alloc_global.c file in which rtl_allocateMemory function
  rounding up allocation requests to be aligned on a 8 byte boundary without
  checking the rounding results, in an integer overflow condition.");

  script_tag(name:"solution", value:"Upgrade to OpenOffice 2.4.1 or later.");

  script_tag(name:"summary", value:"OpenOffice is prone to a heap based buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
keys = registry_enum_keys(key:key);
foreach item (keys)
{
  if("OpenOffice.org" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    if((egrep(pattern:"^([01]\..*|2\.([0-3](\..*)?|4(\.([0-8]?[0-9]?" +
                      "[0-9]?[0-9]|9[0-2][0-9][0-9]|930[0-9]))?))$",
              string:registry_get_sz(key:key + item, item:"DisplayVersion")))){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
