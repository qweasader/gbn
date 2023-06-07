##############################################################################
# OpenVAS Vulnerability Test
#
# PowerDNS Authoritative Server Buffer Overflow Vulnerability
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

CPE = 'cpe:/a:powerdns:authoritative_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141071");
  script_version("2021-06-24T11:00:30+0000");
  script_tag(name:"last_modification", value:"2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-05-09 16:07:28 +0700 (Wed, 09 May 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-31 15:58:00 +0000 (Mon, 31 Aug 2020)");

  script_cve_id("CVE-2018-1046");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"An issue has been found in the dnsreplay tool provided with PowerDNS
Authoritative, where replaying a specially crafted PCAP file can trigger a stack-based buffer overflow, leading to
a crash and potentially arbitrary code execution. This buffer overflow only occurs when the ecs-stamp option of
dnsreplay is used.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative Server versions 4.0.0 until 4.1.1.");

  script_tag(name:"solution", value:"Upgrade to version 4.1.2 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2018-02.html");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.2");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(0);
