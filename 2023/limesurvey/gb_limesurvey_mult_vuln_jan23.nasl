# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.126323");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-02-01 09:19:19 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-04 01:57:00 +0000 (Sat, 04 Feb 2023)");

  script_cve_id("CVE-2022-48008", "CVE-2022-48010");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("LimeSurvey <= 5.4.15 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-48008: An arbitrary file upload vulnerability in the plugin manager.

  - CVE-2022-48010: A stored cross-site scripting (XSS in the component
  /index.php/surveyAdministration/rendersidemenulink?subactionsurveytexts.");

  script_tag(name:"affected", value:"LimeSurvey version 5.4.15 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 01st February, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/Sakura-501/LimeSurvey-5.4.15-PluginUploadtoRCE");
  script_xref(name:"URL", value:"https://github.com/Sakura-501/LimeSurvey-5.4.15-Stored-XSS-in-surveytexts");

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

if (version_is_less_equal(version: version, test_version: "5.4.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
