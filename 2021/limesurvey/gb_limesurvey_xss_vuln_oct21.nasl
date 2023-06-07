# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:limesurvey:limesurvey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146881");
  script_version("2022-10-13T10:20:57+0000");
  script_tag(name:"last_modification", value:"2022-10-13 10:20:57 +0000 (Thu, 13 Oct 2022)");
  script_tag(name:"creation_date", value:"2021-10-11 11:46:32 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-18 20:01:00 +0000 (Mon, 18 Oct 2021)");

  script_cve_id("CVE-2021-42112");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey 3.x-LTS < 3.27.19 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"LimeSurvey is prone to a cross-site scripting (XSS) vulnerability
  in assets/scripts/modaldialog.js and assets/scripts/uploader.js.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"LimeSurvey version 3.x-LTS prior to 3.27.19.");

  script_tag(name:"solution", value:"Update to version 3.27.19 or later.");

  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/pull/2044");
  script_xref(name:"URL", value:"https://www.on-x.com/sites/default/files/on-x_-_security_advisory_-_limesurvey_-_cve-2021-42112.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.27.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.27.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
