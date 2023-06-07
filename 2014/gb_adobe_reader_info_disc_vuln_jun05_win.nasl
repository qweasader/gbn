###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader Information Disclosure Vulnerability Jun05 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804255");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2005-1306");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-04-15 17:57:59 +0530 (Tue, 15 Apr 2014)");
  script_name("Adobe Reader Information Disclosure Vulnerability Jun05 (Windows)");

  script_tag(name:"summary", value:"Adobe Reader is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exists due to an error in the adobe reader control which allows reading
the contents of certain text files.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain knowledge of potentially
sensitive information.");
  script_tag(name:"affected", value:"Adobe Reader version 7.0.0 and 7.0.1 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader 7.0.5 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/15698");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13962");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1014212");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/331710.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^7\.") {
  if(version_is_equal(version:vers, test_version:"7.0.0")||
     version_is_equal(version:vers, test_version:"7.0.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
