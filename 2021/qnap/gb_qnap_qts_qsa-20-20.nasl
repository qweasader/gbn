# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145187");
  script_version("2022-05-25T12:01:55+0000");
  script_tag(name:"last_modification", value:"2022-05-25 12:01:55 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2021-01-18 07:19:10 +0000 (Mon, 18 Jan 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-30 16:15:00 +0000 (Wed, 30 Dec 2020)");

  script_cve_id("CVE-2020-25847");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Command Injection Vulnerability (QSA-20-20)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to an authenticated command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A command injection vulnerability has been reported to affect QTS. If
  exploited, this vulnerability allows attackers to execute arbitrary commands in a compromised application.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.4.x and 4.5.x.");

  script_tag(name:"solution", value:"Update to version 4.5.1.1495 build 20201123 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-20-20");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^4\.[45]" && version_is_less(version: version, test_version: "4.5.1_20201123")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.1_20201123");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
