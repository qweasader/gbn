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
  script_oid("1.3.6.1.4.1.25623.1.0.145170");
  script_version("2021-08-17T09:01:01+0000");
  script_tag(name:"last_modification", value:"2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-01-15 08:17:06 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-05 14:20:00 +0000 (Tue, 05 Jan 2021)");

  script_cve_id("CVE-2020-25797", "CVE-2020-25798", "CVE-2020-25799");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 3.21.2 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - XSS in the Add Participants Function (CVE-2020-25797)

  - XSS via parameter ParticipantAttributeNamesDropdown of the Attributes on the central participant database
    page (CVE-2020-25798)

  - XSS in the Quota component of the Survey page (CVE-2020-25799)");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to inject arbitrary HTML
  and JavaScript into the site.");

  script_tag(name:"affected", value:"LimeSurvey version 3.21.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.21.2 or later.");

  script_xref(name:"URL", value:"https://bugs.limesurvey.org/view.php?id=15680");
  script_xref(name:"URL", value:"https://bugs.limesurvey.org/view.php?id=15672");
  script_xref(name:"URL", value:"https://bugs.limesurvey.org/view.php?id=15681");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.21.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.21.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
