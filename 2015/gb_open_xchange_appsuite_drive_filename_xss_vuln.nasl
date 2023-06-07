# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806074");
  script_version("2022-12-12T10:22:32+0000");
  script_cve_id("CVE-2014-2393");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-12 10:22:32 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"creation_date", value:"2015-10-06 12:24:33 +0530 (Tue, 06 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite Drive File XSS Vulnerability (Apr 2014)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to 'Drive filename' is
  not properly handled during use of the composer to add an e-mail attachment.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to inject arbitrary web script or HTML leading to session hijacking or
  triggering unwanted actions via the web interface.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions 7.4.1
  before 7.4.1-rev11, and 7.4.2 before 7.4.2-rev13");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) AppSuite
  version 7.4.1-rev11 or 7.4.2-rev13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/126066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/531762");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];

if (version !~ "^7\.4\.2")
  exit(99);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

location = infos["location"];
version += "." + revision;

if (version_in_range(version: version, test_version: "7.4.2", test_version2: "7.4.2.12"))
  fix = "7.4.2.13";

else if (version_in_range(version: version, test_version: "7.4.1", test_version2: "7.4.1.10"))
  fix = "7.4.1.11";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);