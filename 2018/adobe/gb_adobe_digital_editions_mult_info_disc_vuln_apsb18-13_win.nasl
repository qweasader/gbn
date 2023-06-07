##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Digital Editions Multiple Information Disclosure Vulnerabilities-APSB18-13 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813081");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-4925", "CVE-2018-4926");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-22 13:37:00 +0000 (Fri, 22 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-04-12 11:41:52 +0530 (Thu, 12 Apr 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Editions Multiple Information Disclosure Vulnerabilities-APSB18-13 (Windows)");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an out-of-bounds
  read error and a stack overflow error caused by unsafe processing of specially
  crafted 'epub' files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Adobe Digital Edition prior to 4.5.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.8 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb18-13.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103712");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
digitalVer = infos['version'];
digitalPath = infos['location'];

if(version_is_less(version:digitalVer, test_version:"4.5.8"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.8", install_path:digitalPath);
  security_message(data:report);
  exit(0);
}
exit(0);
