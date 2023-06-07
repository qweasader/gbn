##############################################################################
# OpenVAS Vulnerability Test
#
# PowerDNS Recursor Crafted Answer DoS Vulnerability
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

CPE = 'cpe:/a:powerdns:recursor';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141655");
  script_version("2021-06-24T11:00:30+0000");
  script_tag(name:"last_modification", value:"2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-11-07 09:53:35 +0700 (Wed, 07 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2018-10851");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor Crafted Answer DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"An issue has been found in PowerDNS Recursor allowing a malicious
authoritative server to cause a memory leak by sending specially crafted records. The issue is due to the fact
that some memory is allocated before the parsing and is not always properly released if the record is malformed.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Recursor versions 3.2 until 4.1.4.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.9, 4.1.5 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-04.html");

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

if (version_in_range(version: version, test_version: "3.2", test_version2: "4.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.9");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.5");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(0);
