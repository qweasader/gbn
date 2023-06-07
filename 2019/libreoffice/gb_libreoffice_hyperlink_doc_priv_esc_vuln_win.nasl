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

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815421");
  script_version("2021-10-04T14:22:38+0000");
  script_cve_id("CVE-2019-9847");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-10 15:11:00 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2019-07-19 17:12:56 +0530 (Fri, 19 Jul 2019)");
  script_name("LibreOffice Hyperlink Document Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to when processing a hyperlink
  target explicitly activated by the user there was no judgment made on whether
  the target was an executable file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to launch executable targets unconditionally on activation.");

  script_tag(name:"affected", value:"LibreOffice prior to 6.1.6 and 6.2 series prior to 6.2.3.");

  script_tag(name:"solution", value:"Update to version 6.1.6, 6.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2019-9847/");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"6.1.6")) {
  fix = "6.1.6";
}

else if(vers =~ "^6\.2\." && version_is_less(version:vers, test_version:"6.2.3")) {
  fix = "6.2.3";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);