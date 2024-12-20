# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:squid-cache:squid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106484");
  script_version("2024-02-02T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:11 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-12-19 14:15:02 +0700 (Mon, 19 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 03:03:55 +0000 (Fri, 02 Feb 2024)");

  script_cve_id("CVE-2016-10003");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid 3.5.x < 3.5.23, 4.0.x < 4.0.17 Information Disclosure Vulnerability (SQUID-2016:10) - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Squid is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to incorrect comparison of request headers Squid can deliver
  responses containing private data to clients it should not have reached.");

  script_tag(name:"impact", value:"This problem allows a remote attacker to discover private and
  sensitive information about another clients browsing session. Potentially including credentials
  which allow access to further sensitive resources.

  This problem only affects Squid configured to use the Collapsed Forwarding feature.");

  script_tag(name:"affected", value:"Squid versions 3.5.x and 4.0.x.");

  script_tag(name:"solution", value:"Update to version 3.5.23, 4.0.17 or later.");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_10.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.5.0", test_version2: "3.5.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.23");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.17");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
