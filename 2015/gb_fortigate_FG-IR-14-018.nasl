# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/o:fortinet:fortios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105203");
  script_version("2022-03-17T02:33:02+0000");
  script_tag(name:"last_modification", value:"2022-03-17 02:33:02 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-02-11 12:17:13 +0100 (Wed, 11 Feb 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-0224", "CVE-2014-0221", "CVE-2014-0195");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiGate Multiple Vulnerabilities in OpenSSL (FG-IR-14-018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortigate_consolidation.nasl");
  script_mandatory_keys("fortinet/fortigate/detected");

  script_tag(name:"summary", value:"Fortinet FortiGate is prone to multiple vulnerabilities in
  OpenSSL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"CVE-2014-0224 may allow an attacker with a privileged network
  position (man-in-the-middle) to decrypt SSL encrypted communications.

  CVE-2014-0221 may allow an attacker to crash a DTLS client with an invalid handshake.

  CVE-2014-0195 can result in a buffer overrun attack by sending invalid DTLS fragments to an
  OpenSSL DTLS client or server.

  CVE-2014-0198 and CVE-2010-5298 may allow an attacker to cause a denial of service under certain
  conditions, when SSL_MODE_RELEASE_BUFFERS is enabled.");

  script_tag(name:"affected", value:"FortiGate prior to version 4.3.16 (build 686), version 5.2.0
  (build 589) and 5.0.8 (build 291).");

  script_tag(name:"solution", value:"Update to version 4.3.16 (build 686), 5.2.0 (build 589), 5.0.8
  (build 291) or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-14-018");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!get_kb_item("fortinet/fortigate/detected"))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("fortinet/fortigate/build");

if (version_is_equal(version: version, test_version: "5.2.0")) {
  if (!build || version_is_less(version: build, test_version: "589")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.2.0", fixed_build: "589");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.8")) {
  if (version_is_less(version: version, test_version: "5.0.8")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.0.8", fixed_build: "281");
    security_message(port: 0, data: report);
    exit(0);
  } else {
    if (!build || version_is_less(version: build, test_version: "281")) {
      report = report_fixed_ver(installed_version: version, installed_build: build,
                                fixed_version: "5.0.8", fixed_build: "281");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (version_is_less_equal(version: version, test_version: "4.3.16")) {
  if (version_is_less(version: version, test_version: "4.3.16")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "4.3.16", fixed_build: "686");
    security_message(port: 0, data: report);
    exit(0);
  } else {
    if (!build || version_is_less(version: build, test_version: "686")) {
      report = report_fixed_ver(installed_version: version, installed_build: build,
                                fixed_version: "4.3.16", fixed_build: "686");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
