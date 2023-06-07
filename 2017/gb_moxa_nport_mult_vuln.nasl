# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:moxa:nport_";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106589");
  script_version("2021-09-09T10:07:02+0000");
  script_tag(name:"last_modification", value:"2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-02-16 09:18:30 +0700 (Thu, 16 Feb 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-17 18:12:00 +0000 (Fri, 17 Feb 2017)");

  script_cve_id("CVE-2016-9361", "CVE-2016-9369", "CVE-2016-9363", "CVE-2016-9371", "CVE-2016-9365",
                "CVE-2016-9366", "CVE-2016-9348", "CVE-2016-9367");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa NPort Devices Multiple Vulnerabilities (Dec 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_moxa_nport_consolidation.nasl");
  script_mandatory_keys("moxa/nport/detected");

  script_tag(name:"summary", value:"Moxa NPort devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Moxa NPort devices are prone to multiple vulnerabilities:

  - CVE-2016-9361: Administration passwords can be retried without authenticating

  - CVE-2016-9369: Firmware can be updated over the network without authentication, which may allow
  remote code execution.

  - CVE-2016-9363: Buffer overflow vulnerability may allow an unauthenticated attacker to remotely
  execute arbitrary code.

  - CVE-2016-9371: User-controlled input is not neutralized before being output to web page.

  - CVE-2016-9365: Requests are not verified to be intentionally submitted by the proper user.

  - CVE-2016-9366: An attacker can freely use brute force to determine parameters needed to bypass
  authentication.

  - CVE-2016-9348: A configuration file contains parameters that represent passwords in plaintext.

  - CVE-2016-9367: The amount of resources requested by a malicious actor is not restricted, leading
  to a denial-of-service caused by resource exhaustion.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities could lead to
  the complete compromise of an affected system.");

  script_tag(name:"affected", value:"Moxa NPort 5110, 5130/5150 Series, 5200 Series, 5400 Series,
  5600 Series, 5100A Series, P5150A, 5200A Series, 5150AI-M12 Series, 5250AI-M12 Series, 5450AI-M12
  Series, 5600-8-DT Series, 5600-8-DTL Series, 6x50 Series and IA5450A.");

  script_tag(name:"solution", value:"Moxa has released new firmware versions which addresses the
  identified vulnerabilities.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-336-02");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:moxa:nport_5[1246]")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/o:moxa:nport_5110") {
  if (version_is_less(version: version, test_version: "2.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.7");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~"^cpe:/o:moxa:nport_51[35]0") {
  if (version_is_less(version: version, test_version: "3.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.7");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~ "^cpe:/o:moxa:nport_52[0-9]{2}_firmware") {
  if (version_is_less(version: version, test_version: "2.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.9");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~ "^cpe:/o:moxa:nport_54[0-9]{2}_firmware") {
  if (version_is_less(version: version, test_version: "3.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.12");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~ "^cpe:/o:moxa:nport_56[0-9]{2}") {
  if (version_is_less(version: version, test_version: "3.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.8");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~ "^cpe:/o:moxa:nport_5[12][0-9]{2}a_firmware" || cpe =~ "^cpe:/o:moxa:nport_5600-8-dtl") {
  if (version_is_less(version: version, test_version: "1.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.4");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~ "^cpe:/o:moxa:nport_5(1|2|4)50ai-m12") {
  if (version_is_less(version: version, test_version: "1.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.3");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~ "^cpe:/o:moxa:nport_5600-8-dt") {
  if (version_is_less(version: version, test_version: "2.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.5");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~ "^cpe:/o:moxa:nport_5600-8-dtl") {
  if (version_is_less(version: version, test_version: "1.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.4");
    security_message(port: 0, data: report);
  }
  exit(0);
}

# nb: The model check is correct, don't escape the "." because this should catch 6x50 series.
if (cpe =~ "^cpe:/o:moxa:nport_6.50") {
  if (version_is_less(version: version, test_version: "1.16")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.16");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (cpe =~ "^cpe:/o:moxa:nport_5450a") {
  if (version_is_less(version: version, test_version: "1.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.4");
    security_message(port: 0, data: report);
  }
  exit(0);
}

exit(99);