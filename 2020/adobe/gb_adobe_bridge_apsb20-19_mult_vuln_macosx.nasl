# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:bridge_cc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816896");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-9555", "CVE-2020-9562", "CVE-2020-9563", "CVE-2020-9568",
                "CVE-2020-9553", "CVE-2020-9557", "CVE-2020-9558", "CVE-2020-9554",
                "CVE-2020-9556", "CVE-2020-9559", "CVE-2020-9560", "CVE-2020-9561",
                "CVE-2020-9564", "CVE-2020-9565", "CVE-2020-9569", "CVE-2020-9566",
                "CVE-2020-9567");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-29 15:51:00 +0000 (Mon, 29 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-04-29 11:33:39 +0530 (Wed, 29 Apr 2020)");
  script_name("Adobe Bridge Security Update (APSB20-19) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Bridge is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A stack-based buffer overflow error.

  - Multiple heap overflow errors.

  - A memory corruption error.

  - Multiple out-of-bounds read error.

  - Multiple out-of-bounds write error.

  - Multiple use-after-free errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Adobe Bridge 10.0.1 and earlier versions.");

  script_tag(name:"solution", value:"Update to version 10.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb20-19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Bridge/CC/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"10.0.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.0.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);