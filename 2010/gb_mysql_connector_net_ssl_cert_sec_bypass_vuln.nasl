###############################################################################
# OpenVAS Vulnerability Test
#
# MySQL Connector/Net SSL Certificate Validation Security Bypass Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801205");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-07 15:36:02 +0200 (Fri, 07 May 2010)");
  script_cve_id("CVE-2009-4833");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("MySQL Connector/Net SSL Certificate Validation Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35514");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=38700");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51406");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform man-in-the-middle
  attacks, which will aid in further attacks.");
  script_tag(name:"affected", value:"MySQL Connector/Net 6.0.3 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by improper verification of certificates when using SSL
  connections that allow remote attackers to conduct spoofing attacks.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the latest version of MySQL Connector/Net 6.0.4 or later.");
  script_tag(name:"summary", value:"MySQL Connector/Net is prone to a security bypass vulnerability.");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## COnfirm it's Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\MySQL AB\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

enumKeys = registry_enum_keys(key:key);

## Exit if no keys exists
if(isnull(enumKeys)){
  exit(0);
}

foreach item (enumKeys)
{
  if("MySQL Connector/Net" >< item)
  {
    ver = registry_get_sz(key:key+item, item:"Version");

    if(ver && version_is_less(version: ver, test_version: "6.0.4")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
