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

CPE = "cpe:/a:qnap:surveillance_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145424");
  script_version("2021-08-17T09:01:01+0000");
  script_tag(name:"last_modification", value:"2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-02-22 04:00:17 +0000 (Mon, 22 Feb 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-22 19:28:00 +0000 (Mon, 22 Feb 2021)");

  script_cve_id("CVE-2020-2501", "CVE-2021-28797");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Just get the major version

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Surveillance Station Buffer Overflow Vulnerability (QSA-21-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_qnap_nas_surveillance_station_detect.nasl");
  script_mandatory_keys("qnap/surveillance/detected");

  script_tag(name:"summary", value:"QNAP QTS Surveillance Station is prone to a stack buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A stack-based buffer overflow vulnerability has been reported to affect
  QNAP NAS devices running Surveillance Station. If exploited, this vulnerability allows attackers to execute
  arbitrary code.");

  script_tag(name:"affected", value:"QNAP QTS Surveillance Station prior to versions 5.1.5.3.3 (for ARM CPU
  NAS (32bit OS) and x86 CPU NAS (32bit OS)) or 5.1.5.4.3 (for ARM CPU NAS (64bit OS) and x86 CPU NAS (64bit OS)).");

  script_tag(name:"solution", value:"Update to version 5.1.5.3.3 (32bit OS), 5.1.5.4.3 (64bit OS) or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-07");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.5.3.3 / 5.1.5.4.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
