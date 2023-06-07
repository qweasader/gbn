###############################################################################
# OpenVAS Vulnerability Test
#
# OpenOffice senddoc Insecure Temporary File Creation Vulnerability (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800128");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2008-4937");
  script_name("OpenOffice senddoc Insecure Temporary File Creation Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/10/30/2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30925");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to delete or corrupt
  sensitive files, which may result in a denial of service condition.");

  script_tag(name:"affected", value:"OpenOffice.org 2.4.1 on Windows (Any).");

  script_tag(name:"insight", value:"The flaw exists due to OpenOffice 'senddoc' which creates temporary files in an
  insecure manner, that allows users to overwrite files via a symlink attack
  on a /tmp/log.obr.##### temporary file.");

  script_tag(name:"solution", value:"Upgrade OpenOffice to a later version.");

  script_tag(name:"summary", value:"OpenOffice is prone to an insecure temporary file creation vulnerability.");

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
    openOffVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(openOffVer == "2.4.9310"){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
