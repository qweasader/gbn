# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127047");
  script_version("2022-07-28T10:10:25+0000");
  script_tag(name:"last_modification", value:"2022-07-28 10:10:25 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-06-16 12:35:21 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-15 03:17:00 +0000 (Fri, 15 Apr 2022)");

  script_cve_id("CVE-2021-32156", "CVE-2021-32157", "CVE-2021-32158", "CVE-2021-32159",
                "CVE-2021-32160", "CVE-2021-32161", "CVE-2021-32162");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Webmin <= 1.994 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32156: A cross-site request forgery (CSRF) vulnerability exists via
  the Scheduled Cron Jobs feature.

  - CVE-2021-32157: A cross-site scripting (XSS) vulnerability exists via the Scheduled Cron Jobs
  feature.

  - CVE-2021-32158: An XSS vulnerability exists via the Upload and Download feature.

  - CVE-2021-32159: A CSRF vulnerability exists via the Upload and Download feature.

  - CVE-2021-32160: An XSS vulnerability exists through the Add Users feature.

  - CVE-2021-32161: An XSS vulnerability exists through the File Manager feature.

  - CVE-2021-32162: A CSRF vulnerability exists through the File Manager feature.");

  script_tag(name:"affected", value:"Webmin version 1.994 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 16th June, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-32157");
  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-32158");
  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-32159");
  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-32160");
  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-32161");
  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-32162");

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

if (version_is_less_equal(version: version, test_version: "1.994")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
