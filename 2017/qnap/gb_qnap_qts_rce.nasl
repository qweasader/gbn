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
  script_oid("1.3.6.1.4.1.25623.1.0.107274");
  script_version("2022-05-25T21:46:57+0000");
  script_tag(name:"last_modification", value:"2022-05-25 21:46:57 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2017-12-13 13:24:30 +0100 (Wed, 13 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-04 18:45:00 +0000 (Thu, 04 Jan 2018)");

  script_cve_id("CVE-2017-17029", "CVE-2017-17030", "CVE-2017-17031", "CVE-2017-17032", "CVE-2017-17033",
                "CVE-2017-14746", "CVE-2017-15275", "CVE-2017-7631");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Unauthenticated Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is vulnerable to unauthenticated remote code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to lack of proper bounds checking in authLogin.cgi");

  script_tag(name:"impact", value:"It is possible to overflow a stack buffer with a specially crafted
  HTTP request and hijack the control flow to achieve arbitrary code execution.");

  script_tag(name:"affected", value:"QNAP QTS version 4.2.x prior to 4.2.6 build 20171208 and
  4.3.x prior to 4.3.4 build 20171213.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20171208, 4.3.4.0416 (beta 3)
   build 20171213 or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3565");
  script_xref(name:"URL", value:"https://www.qnap.com/de-de/releasenotes/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.0", test_version_up: "4.3.4_20171213")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4_20171213");
  security_message(port: 0, data: report);
  exit(0);
}
if (version_in_range_exclusive(version: version, test_version_lo: "4.2.0", test_version_up: "4.2.6_20171208")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6_20171208");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
