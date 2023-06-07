# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.813195");
  script_version("2022-05-25T12:01:55+0000");
  script_cve_id("CVE-2018-0711");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-05-25 12:01:55 +0000 (Wed, 25 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-06 13:15:00 +0000 (Wed, 06 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-05-18 09:52:09 +0530 (Fri, 18 May 2018)");

  script_name("QNAP QTS XSS Vulnerability (nas-201804-27)");

  script_tag(name:"summary", value:"QNAP QTS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists as the application does not properly
  filter HTML code from user-supplied input before displaying the input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  conduct XSS attacks.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.3.3 build 20180126 and earlier,
  4.3.4 build 20180315 and earlier.");

  script_tag(name:"solution", value:"Upgrade to QNAP QTS 4.3.3 build 20180402 or 4.3.4
  build 20180413 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201804-27");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.3.3_20180126")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20180402");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.4", test_version2: "4.3.4_20180315")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4_20180413");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
