###############################################################################
# OpenVAS Vulnerability Test
#
# IBM RBD Web Services Information Disclosure Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802685");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-3319");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-12-19 19:17:26 +0530 (Wed, 19 Dec 2012)");
  script_name("IBM RBD Web Services Information Disclosure Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50755/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55718");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78726");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21612314");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to obtain potentially
  sensitive information.");
  script_tag(name:"affected", value:"IBM Rational Business Developer version 8.x to 8.0.1.3 on Windows");
  script_tag(name:"insight", value:"Error exists within web service created with the IBM Rational Business
  Developer product.");
  script_tag(name:"solution", value:"Upgrade to IBM Rational Business Developer version 8.0.1.4 or later.");
  script_tag(name:"summary", value:"IBM Rational Business Developer is prone to an information disclosure vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

ibmFile = "IBM_Rational_Business_Developer.8.0.0.swtag";
fxPkgVer = [ "8.0.1", "1.8.0.1.1", "2.8.0.1.2", "3.8.0.1.3" ];
fxPkgFile = "IBM_Rational_Business_Developer_Fix_Pack_";
ibmKey = "SOFTWARE\\IBM\\SDP\\license\\35";

if(!registry_key_exists(key:ibmKey)) exit(0);

rbdExist = registry_get_sz(key:ibmKey, item:"8.0");

if (!rbdExist) exit(0);

## built a key to get product installation path
ibmKey = ibmKey - "SDP\\license\\35" + "Installation Manager";

rbdPath = registry_get_sz(key:ibmKey, item:"location");

if (rbdPath && rbdPath =~ "Installation Manager")
{
  rbdPath = rbdPath - "Installation Manager" + "SDP\\rbd\\properties\\version\\";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rbdPath);
  filePath = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",string:rbdPath + ibmFile);
  rbdFile = smb_read_file(share:share, file:filePath, offset:0, count:250);

  if (rbdFile && rbdFile =~ "ProductName>IBM Rational Business Developer<" &&
      rbdFile =~ ">8.0.0<")
  {
    foreach fxp (fxPkgVer)
    {
      fxPkgPath = filePath - ibmFile + fxPkgFile + fxp + ".fxtag";
      rbdFile = smb_read_file(share:share, file:fxPkgPath, offset:0, count:250);

      if (rbdFile && rbdFile =~ "FixName>IBM Rational Business Developer Fix Pack" &&
          rbdFile =~ "FixVersion>8.0.1(.[0-3])?<")
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
