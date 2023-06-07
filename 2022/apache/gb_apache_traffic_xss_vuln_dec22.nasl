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

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149036");
  script_version("2022-12-20T10:11:13+0000");
  script_tag(name:"last_modification", value:"2022-12-20 10:11:13 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-20 04:20:54 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2022-40743");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) 9.x < 9.1.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");

  script_tag(name:"summary", value:"Apache Traffic Server (ATS) is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An improper input validation vulnerability in the xdebug plugin
  can lead to cross-site scripting and cache poisoning attacks.");

  script_tag(name:"affected", value:"Apache Traffic Server version 9.0.0 through 9.1.3.");

  script_tag(name:"solution", value:"Update to version 9.1.4 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/mrj2lg4s0hf027rk7gz8t7hbn9xpfg02");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
