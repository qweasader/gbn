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

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143222");
  script_version("2022-05-25T12:01:55+0000");
  script_tag(name:"last_modification", value:"2022-05-25 12:01:55 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2019-12-05 04:19:49 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-06 19:14:00 +0000 (Fri, 06 Dec 2019)");

  script_cve_id("CVE-2019-7197");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS XSS Vulnerability (NAS-201911-26)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a stored cross-site scripting vulnerability
  in QTS Event Notification.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stored cross-site scripting (XSS) vulnerability has been
  reported to affect multiple versions of QTS. If exploited, this vulnerability may allow an attacker
  to inject and execute scripts on the administrator console.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.6, 4.3.3, 4.3.4, 4.3.6 and 4.4.1.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20190921, 4.3.3 build 20190921,
  4.3.4 build 20190921, 4.3.6 build 20190919, 4.4.1 build 20190918 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201911-26");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "4.2.6", test_version2: "4.2.6_20190920")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6_20190921");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.3", test_version2: "4.3.3_20190920")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20190921");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.4", test_version2: "4.3.4_20190920")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4_20190921");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.6", test_version2: "4.3.6_20190918")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6_20190919");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.1", test_version2: "4.4.1_20190917")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.1_20190918");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
