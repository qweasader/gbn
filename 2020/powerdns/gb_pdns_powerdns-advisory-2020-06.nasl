# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:powerdns:authoritative_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144704");
  script_version("2021-08-12T06:00:50+0000");
  script_tag(name:"last_modification", value:"2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-10-05 04:46:54 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-08 15:17:00 +0000 (Thu, 08 Oct 2020)");

  script_cve_id("CVE-2020-24696", "CVE-2020-24697", "CVE-2020-24698");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server Multiple Vulnerabilities (2020-06)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to multiple vulnerabilities in the
  GSS-TSIG support.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A remote, unauthenticated attacker can trigger a race condition leading to a crash, or possibly arbitrary code
    execution, by sending crafted queries with a GSS-TSIG signature (CVE-2020-24696)

  - A remote, unauthenticated attacker can cause a denial of service by sending crafted queries with a GSS-TSIG
    signature (CVE-2020-24697)

  - A remote, unauthenticated attacker might be able to cause a double-free, leading to a crash or possibly
    arbitrary code execution by sending crafted queries with a GSS-TSIG signature (CVE-2020-24698)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative prior to version 4.4.0.");

  script_tag(name:"solution", value:"Update to version 4.4.0 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2020-06.html");

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

if (version_is_less(version: version, test_version: "4.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.0");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
