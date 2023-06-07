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
  script_oid("1.3.6.1.4.1.25623.1.0.147747");
  script_version("2022-04-27T08:53:35+0000");
  script_tag(name:"last_modification", value:"2022-04-27 08:53:35 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-03 04:34:19 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 19:42:00 +0000 (Thu, 10 Mar 2022)");

  script_cve_id("CVE-2022-0824", "CVE-2022-0829");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Webmin <= 1.984 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-0824: Improper access control leads to remote code execution (RCE)

  - CVE-2022-0829: Improper authorization");

  script_tag(name:"affected", value:"Webmin version 1.984 and prior.");
  # nb: There was no version 1.985 or similar in between according to https://www.webmin.com/changes.html
  script_tag(name:"solution", value:"Update to version 1.990 or later.");

  script_xref(name:"URL", value:"https://www.webmin.com/security.html");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/d0049a96-de90-4b1a-9111-94de1044f295/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/f2d0389f-d7d1-4f34-9f9d-268b0a0da05e/");
  script_xref(name:"URL", value:"https://github.com/webmin/webmin/commit/eeeea3c097f5cc473770119f7ac61f1dcfa671b9");
  script_xref(name:"URL", value:"https://github.com/webmin/webmin/commit/39ea464f0c40b325decd6a5bfb7833fa4a142e38");

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

if (version_is_less_equal(version: version, test_version: "1.984")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.990", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
