# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:paessler:prtg_network_monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112728");
  script_version("2021-08-16T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-04-06 07:48:21 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-07 12:38:00 +0000 (Tue, 07 Apr 2020)");

  script_cve_id("CVE-2020-11547");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PRTG Network Monitor < 20.1.57.1745 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows remote unauthenticated attackers to
  obtain information about probes running or the server itself (such as CPU usage, memory,
  Windows version or internal statistics) via an HTTP request.");

  script_tag(name:"affected", value:"PRTG Network Monitor prior to version 20.1.57.1745.");

  script_tag(name:"solution", value:"Update to version 20.1.57.1745 or later.");

  script_xref(name:"URL", value:"https://github.com/ch-rigu/PRTG-Network-Monitor-Information-Disclosure");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "20.1.57.1745")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.1.57.1745", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
