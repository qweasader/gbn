###############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND Access Control Vulnerability (Jun 2018) - Linux
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141179");
  script_version("2021-05-28T06:00:18+0200");
  script_tag(name:"last_modification", value:"2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)");
  script_tag(name:"creation_date", value:"2018-06-13 11:46:01 +0700 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-30 17:15:00 +0000 (Fri, 30 Aug 2019)");

  script_cve_id("CVE-2018-5738");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("ISC BIND Access Control Vulnerability (Jun 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Some versions of BIND can improperly permit recursive query service to
  unauthorized clients.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ISC BIND 9.9.12, 9.10.7, 9.11.3, 9.12.0->9.12.1-P2, 9.13.0, 9.9.12-S1,
  9.10.7-S1, 9.11.3-S1, and 9.11.3-S2.");

  script_tag(name:"solution", value:"See the vendor advisory for workarounds.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01616");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

affected = make_list('9.9.12',
                     '9.10.7',
                     '9.11.3',
                     '9.13.0',
                     '9.9.12s1',
                     '9.10.7s1',
                     '9.11.3s1',
                     '9.11.3s2');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Workaround", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

if (version_in_range(version: version, test_version: "9.12.0", test_version2: "9.12.1p2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Workaround", install_path: location);
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
