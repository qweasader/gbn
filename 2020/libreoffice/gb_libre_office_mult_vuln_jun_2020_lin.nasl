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

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817257");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-12802", "CVE-2020-12803");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-27 00:15:00 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-03 13:34:53 +0530 (Mon, 03 Aug 2020)");
  script_name("Libre Office Multiple Vulnerabilities(June-2020) - Linux");

  script_tag(name:"summary", value:"Libre Office is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error exists while loading remote graphics links from docx documents.

  - An error in ODF documents.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to overwrite local files and disclose sensitive information.");

  script_tag(name:"affected", value:"Libre Office before version 6.4.4.");

  script_tag(name:"solution", value:"Update to Libre Office 6.4.4
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2020-12802");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2020-12803");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_lin.nasl");
  script_mandatory_keys("LibreOffice/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"6.4.4")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.4.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);