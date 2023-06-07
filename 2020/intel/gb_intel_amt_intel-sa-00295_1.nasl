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

CPE = "cpe:/h:intel:active_management_technology";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144117");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-06-17 04:26:18 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-18 13:15:00 +0000 (Thu, 18 Mar 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-0531", "CVE-2020-0532", "CVE-2020-0537", "CVE-2020-0538", "CVE-2020-0540",
                "CVE-2020-0594", "CVE-2020-0595", "CVE-2020-0596", "CVE-2020-11899", "CVE-2020-11900");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Multiple Vulnerabilities (INTEL-SA-00295)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");

  script_tag(name:"summary", value:"Potential security vulnerabilities in Intel Active Management Technology
  (AMT) may allow escalation of privilege, denial of service or information disclosure.");

  script_tag(name:"insight", value:"Intel Active Management Technology is prone to multiple vulnerabilities:

  - Improper input validation may allow an authenticated user to potentially enable information disclosure via
    network access. (CVE-2020-0531)

  - Improper input validation may allow an unauthenticated user to potentially enable denial of service or
    information disclosure via adjacent access. (CVE-2020-0532)

  - Improper input validation may allow a privileged user to potentially enable denial of service via network
    access. (CVE-2020-0537)

  - Improper input validation may allow an unauthenticated user to potentially enable denial of service via
    network access. (CVE-2020-0538)

  - Insufficiently protected credentials may allow an unauthenticated user to potentially enable information
    disclosure via network access. (CVE-2020-0540)

  - Out-of-bounds read in IPv6 subsystem may allow an unauthenticated user to potentially enable escalation of
    privilege via network access. (CVE-2020-0594, CVE-2020-11899)

  - Use after free in IPv6 subsystem may allow an unauthenticated user to potentially enable escalation of
    privilege via network access. (CVE-2020-0595, CVE-2020-11900)

  - Improper input validation in DHCPv6 subsystem may allow an unauthenticated user to potentially enable
    information disclosure via network access. (CVE-2020-0596)

  Note: CVE-2020-0594 and CVE-2020-0595 as assigned by Intel correspond to a subset of the CVEs disclosed in the linked
  'Treck IP stacks contain multiple vulnerabilities' advisory (covering the 'Ripple20' called vulnerabilities)
  and are matching CVE-2020-11899 and CVE-2020-11900.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Intel Active Management Technology versions 11.0 through 11.8.76, 11.10
  through 11.11.76, 11.20 through 11.22.76 and 12.0 through 12.0.63.");

  script_tag(name:"solution", value:"Upgrade to version 11.8.77, 11.11.77, 11.22.77, 12.0.64 or later.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00295.html");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/257161");
  script_xref(name:"URL", value:"https://treck.com/vulnerability-response-information/");
  script_xref(name:"URL", value:"https://www.jsof-tech.com/ripple20/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.8.76")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.8.77", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.10", test_version2: "11.11.76")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.11.77", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.20", test_version2: "11.22.76")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.22.77", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.0.63")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.64", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
