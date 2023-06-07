# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:dreamweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815041");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2019-7097");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-04-18 17:01:02 +0530 (Thu, 18 Apr 2019)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Dreamweaver Information Disclosure Vulnerability(APSB19-21)-Mac OS X");

  script_tag(name:"summary", value:"Adobe Dreamweaver is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insecure protocol
  implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information that may lead to further attacks.");

  script_tag(name:"affected", value:"Adobe Dreamweaver versions 19.0 and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Dreamweaver 19.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb19-21.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/107825");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_dreamweaver_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Dreamweaver/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"19.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"19.1", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
