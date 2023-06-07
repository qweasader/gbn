# Copyright (C) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105875");
  script_version("2022-03-17T02:33:02+0000");
  script_tag(name:"last_modification", value:"2022-03-17 02:33:02 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-08-18 11:05:04 +0200 (Thu, 18 Aug 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-22 15:06:00 +0000 (Wed, 22 May 2019)");

  script_cve_id("CVE-2016-6909");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiGate Cookie Parser Buffer Overflow Vulnerability (FG-IR-16-023) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortigate_consolidation.nasl");
  script_mandatory_keys("fortinet/fortigate/detected");

  script_tag(name:"summary", value:"FortiGate firmware (FOS) released before Aug 2012 has a cookie
  parser buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability, when exploited by a crafted HTTP request,
  can result in execution control being taken over.");

  script_tag(name:"affected", value:"FortiGate version 4.1.10 and prior, 4.2.x through 4.2.12 and
  4.3.x through 4.3.8.");

  script_tag(name:"solution", value:"Update to release 5.x. Or update to release 4.3.9 or later for
  models not compatible with FortiOS 5.x.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-023");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!get_kb_item("fortinet/fortigate/detected"))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.1.10") ||
    version_in_range(version: version, test_version: "4.2", test_version2: "4.2.12") ||
    version_in_range(version: version, test_version: "4.3", test_version2: "4.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.x / 4.3.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
