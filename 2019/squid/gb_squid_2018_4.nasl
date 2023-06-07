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

CPE = "cpe:/a:squid-cache:squid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142629");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2019-07-19 07:32:21 +0000 (Fri, 19 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-11 20:54:00 +0000 (Tue, 11 Dec 2018)");

  script_cve_id("CVE-2018-19131");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Security Update Advisory (SQUID-2018:4)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a cross-site scripting vulnerability to incorrect input
  handling when generating HTTPS response messages about TLS errors.");

  script_tag(name:"insight", value:"This problem allows a malicious HTTPS server to trigger error page delivery to
  a client and also inject arbitrary HTML code into the resulting error response.

  This problem is limited to Squid built with TLS / SSL support.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Squid proxy versions 3.1.12.1 through 3.1.23, 3.2.0.4 through
  3.5.28 and 4.x through 4.3.");

  script_tag(name:"solution", value:"Update to version 4.4 or later.");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2018_4.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.1.12.1", test_version2: "3.1.23") ||
    version_in_range(version: version, test_version: "3.2.0.4", test_version2: "3.25.28") ||
    version_in_range(version: version, test_version: "4.0", test_version2: "4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
