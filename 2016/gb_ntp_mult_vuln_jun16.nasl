##############################################################################
# OpenVAS Vulnerability Test
#
# NTP.org 'ntp' Multiple Vulnerabilities (Jun 2016)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106092");
  script_version("2021-10-12T12:01:25+0000");
  script_cve_id("CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_tag(name:"last_modification", value:"2021-10-12 12:01:25 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-06-03 11:18:33 +0700 (Fri, 03 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 13:15:00 +0000 (Fri, 16 Jul 2021)");
  script_name("NTP.org 'ntpd' Multiple Vulnerabilities (Jun 2016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/321640");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd, is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"NTP.org's ntpd is prone multiple vulnerabilities:

  - CRYPTO-NAK denial of service (CVE-2016-4957).

  - Bad authentication demobilizes ephemeral associations (CVE-2016-4953).

  - Processing of spoofed server packets affects peer variables (CVE-2016-4954).

  - Autokey associations may be reset when repeatedly receiving spoofed packets (CVE-2016-4955).

  - Broadcast associations are not covered in Sec 2978 patch, which may be leveraged to flip broadcast
  clients into interleave mode (CVE-2016-4956).");

  script_tag(name:"impact", value:"Unauthenticated, remote attackers may be able to spoof or send
  specially crafted packets to create denial of service conditions.");

  script_tag(name:"affected", value:"Version 4.2.8p7 and prior");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd version 4.2.8p8 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if(revcomp(a:version, b:"4.2.8p8") < 0) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.2.8p8", install_path:location);
  security_message(port:port, data:report, proto:proto);
  exit(0);
}

exit(99);
