###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader 'AcroPDF.DLL' Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804378");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2007-1377");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-04-10 11:24:07 +0530 (Thu, 10 Apr 2014)");
  script_name("Adobe Reader 'AcroPDF.DLL' Denial of Service Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Reader is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exists due to some unspecified error within 'AcroPDF.DLL' ActiveX.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to consume all available
resources and conduct a denial of service.");
  script_tag(name:"affected", value:"Adobe Reader version 8.0 on Mac OS X.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/32896");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22856");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/3430");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer && readerVer =~ "^8")
{
  if(version_is_equal(version:readerVer, test_version:"8.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
