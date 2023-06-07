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

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140260");
  script_version("2022-05-25T21:46:57+0000");
  script_tag(name:"last_modification", value:"2022-05-25 21:46:57 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2017-08-01 10:17:13 +0700 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-11 15:15:00 +0000 (Fri, 11 Sep 2020)");

  script_cve_id("CVE-2017-7876", "CVE-2017-11103", "CVE-2017-1000364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.2.6 build 20170729, 4.3.x < 4.3.3 build 20170727 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"QNAP QTS is prone to multiple vulnerabilities:

  - Multiple vulnerabilities regarding OpenVPN.

  - Multiple OS command injection vulnerabilities. (CVE-2017-7876)

  - Vulnerability in ActiveX controls that could allow for arbitrary code execution on the web client.

  - XSS vulnerability in Storage Manager and Backup Station.

  - 'Orpheus' Lyre' vulnerability in Samba that could be exploited to bypass authentication
  mechanisms. (CVE-2017-11103)

  - Vulnerability in the Linux kernel that could be exploited to circumvent the stack guard page.
  (CVE-2017-1000364)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"QNAP QTS version prior to 4.2.6 build 20170729 and 4.3.x prior
  to 4.3.3.0262 build 20170727");

  script_tag(name:"solution", value:"Update to QTS 4.2.6 build 20170729, QTS 4.3.3.0262
  build 20170727 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-us/releasenotes/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.6_20170729")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6_20170729");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.0", test_version_up: "4.3.3_20170727")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20170727");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
