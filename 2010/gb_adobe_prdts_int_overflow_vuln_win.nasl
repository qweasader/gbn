###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader/Acrobat Font Parsing Integer Overflow Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801419");
  script_version("2022-02-28T15:36:21+0000");
  script_tag(name:"last_modification", value:"2022-02-28 15:36:21 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2862");
  script_name("Adobe Reader/Acrobat Font Parsing Integer Overflow Vulnerability (CVE-2010-2862) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40766");
  script_xref(name:"URL", value:"http://www.zdnet.co.uk/news/security-threats/2010/08/04/adobe-confirms-pdf-security-hole-in-reader-40089737/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation results in memory corruption via a PDF
  file containing a specially crafted TrueType font.");

  script_tag(name:"affected", value:"Adobe Reader version 8.2.3 and 9.3.3

  Adobe Acrobat version 9.3.3 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in 'CoolType.dll'
  when parsing the 'maxCompositePoints' field value in the 'maxp' (Maximum Profile)
  table of a TrueType font.");

  script_tag(name:"solution", value:"Upgrade to version 8.2.4 or 9.3.4 or later.");

  script_tag(name:"summary", value:"Adobe products are prone to a font parsing integer overflow vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:acrobat_reader",
                     "cpe:/a:adobe:acrobat");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if(cpe == "cpe:/a:adobe:acrobat_reader") {
  if(version_is_less_equal(version:vers, test_version:"8.2.3") ||
     version_in_range(version:vers, test_version:"9.0", test_version2:"9.3.3")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"8.2.4 or 9.3.4", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if(cpe == "cpe:/a:adobe:acrobat") {
  if(version_is_less_equal(version:vers, test_version:"9.3.3")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"9.3.4", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
