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

CPE = 'cpe:/a:powerdns:authoritative_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108607");
  script_version("2021-09-06T14:01:33+0000");
  script_tag(name:"last_modification", value:"2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-06-25 07:15:49 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 14:27:00 +0000 (Fri, 02 Oct 2020)");

  script_cve_id("CVE-2019-10162");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server Crafted Zone Records Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to a Denial of Service
  via crafted zone records.");

  script_tag(name:"impact", value:"This flaw allows an authorized user to cause the server to exit
  by inserting a crafted record in a MASTER type zone under their control.");

  script_tag(name:"insight", value:"The issue is due to the fact that the Authoritative Server will exit when it
  runs into a parsing error while looking up the NS/A/AAAA records it is about to use for an outgoing notify.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative before version 4.0.8 and 4.1.x up to and including 4.1.9.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.8, 4.1.10 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/authoritative/security-advisories/powerdns-advisory-2019-04.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.8");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.10");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
