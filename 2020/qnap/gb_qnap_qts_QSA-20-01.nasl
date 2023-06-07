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

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144175");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-06-26 08:41:33 +0000 (Fri, 26 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-13 17:38:00 +0000 (Fri, 13 Nov 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-19943", "CVE-2018-19949", "CVE-2018-19953");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-20-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities in File Station.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws in File Station exist:

  - CVE-2018-19943, CVE-2018-19953: Multiple cross-site scripting (XSS) vulnerabilities

  - CVE-2018-19949: Command injection vulnerability");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.6, 4.3.3, 4.3.4, 4.3.6, 4.4.1 and 4.4.2.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20200421, 4.3.3 build 20200409,
  4.3.4 build 20200408, 4.3.6 build 20200330, 4.4.1 build 20200330, 4.4.2 build 20200410 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-20-01");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "4.2.6", test_version2: "4.2.6_20200420")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6_20200421");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.3", test_version2: "4.3.3_20200408")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20200409");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.4", test_version2: "4.3.4_20200407")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4_20200408");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.6", test_version2: "4.3.6_20200329")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6_20200330");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.1", test_version2: "4.4.1_20200329")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.1_20200330");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.2", test_version2: "4.4.2_20200409")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.2_20200410");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
