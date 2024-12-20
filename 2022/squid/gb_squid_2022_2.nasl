# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148788");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-09-29 08:18:50 +0000 (Thu, 29 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-28 18:04:00 +0000 (Tue, 28 Mar 2023)");

  script_cve_id("CVE-2022-41318");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Buffer Overflow Vulnerability (SQUID-2022:2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a buffer overflow vulnerability in SSPI and
  SMB authentication.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to an incorrect integer overflow protection Squid SSPI and
  SMB authentication helpers are vulnerable to a buffer overflow attack.");

  script_tag(name:"impact", value:"This problem allows a remote client to perform a denial of
  service attack when Squid is configured to use NTLM or Negotiate authentication with one of the
  vulnerable helpers.

  This problem allows a remote client to extract sensitive information from machine memory when
  Squid is configured to use NTLM or Negotiate authentication with one of the vulnerable helpers.
  The scope of this information includes user credentials in decrypted forms, and also arbitrary
  memory areas beyond Squid and the helper itself.

  This attack is limited to authentication helpers built using the libntlmauth library shipped by
  Squid.");

  script_tag(name:"affected", value:"Squid version 2.5.STABLE1 through 2.7.STABLE9, 3.x through
  3.5.28, 4.x through 4.17 and 5.x through 5.6.");

  script_tag(name:"solution", value:"Update to version 5.7 or later.");

  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2022/q3/231");

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

if (version_in_range(version: version, test_version: "2.5", test_version2: "5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
