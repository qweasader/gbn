###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Photoshop CC Information Disclosure Vulnerability-APSB18-28 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:adobe:photoshop_cc2018";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814197");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-15980");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-04 18:07:00 +0000 (Tue, 04 Dec 2018)");
  script_tag(name:"creation_date", value:"2018-11-15 13:26:21 +0530 (Thu, 15 Nov 2018)");
  script_name("Adobe Photoshop CC Information Disclosure Vulnerability-APSB18-28 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Photoshop CC is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to out-of-bounds read
  when handling malicious input. A remote attacker can trick the victim into
  opening specially crafted data, trigger memory corruption and gain access
  to potentially sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclosure of sensitive information which may aid in launching further
  attacks.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2018 19.1.6 and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Photoshop CC 2018 19.1.7, 20.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb18-43.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105905");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pver = infos['version'];
ppath = infos['location'];

if(version_in_range(version:pver, test_version:"19.0", test_version2:"19.1.6"))
{
  report = report_fixed_ver( installed_version: "Adobe Photoshop CC 2018 " + pver, fixed_version: "19.1.7", install_path:ppath);
  security_message(data:report);
}
exit(99);
