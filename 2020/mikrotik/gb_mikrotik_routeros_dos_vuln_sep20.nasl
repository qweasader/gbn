# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144572");
  script_version("2021-07-22T11:01:40+0000");
  script_tag(name:"last_modification", value:"2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-09-15 02:09:54 +0000 (Tue, 15 Sep 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 16:30:00 +0000 (Fri, 18 Sep 2020)");

  script_cve_id("CVE-2020-11881");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.46.7, <= 6.47.3, 7.x DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service vulnerability in the SMB
  server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An array index error in MikroTik RouterOS allows an unauthenticated remote
  attacker to crash the SMB server via modified setup-request packets, aka SUP-12964.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 6.47.3 and prior and 7.x.");

  script_tag(name:"solution", value:"Update to version 6.46.7 (long-term version)");

  script_xref(name:"URL", value:"https://github.com/botlabsDev/CVE-2020-11881");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?f=2&t=166137");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.46.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.46.7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "6\.47" || version =~ "^7\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
