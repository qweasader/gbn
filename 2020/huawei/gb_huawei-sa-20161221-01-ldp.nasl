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

CPE = "cpe:/o:huawei:cloudengine_12800_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143945");
  script_version("2021-08-02T02:00:56+0000");
  script_tag(name:"last_modification", value:"2021-08-02 02:00:56 +0000 (Mon, 02 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-20 04:41:40 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-26 16:00:00 +0000 (Mon, 26 Mar 2018)");

  script_cve_id("CVE-2016-8784");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Memory Leak Vulnerability (huawei-sa-20161221-01-ldp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products are prone to a memory leak vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated attacker may send specific Label Distribution Protocol
  (LDP) packets to the devices. When the values of some parameters in the packet are abnormal, the LDP
  processing module does not release the memory to handle the packet, resulting in memory leak.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to cause memory leak.");

  script_tag(name:"affected", value:"Huawei CloudEngine 12800.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161221-01-ldp-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

patch = get_kb_item("huawei/vrp/patch");

if (version =~ "^V100R003C00" || version =~ "^V100R003C10") {
  if (!patch || version_is_less(version: patch, test_version: "V100R003SPH011")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V100R003SPH011");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^V100R005C00" || version =~ "^V100R005C10") {
  if (!patch || version_is_less(version: patch, test_version: "V100R005SPH005")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V100R005SPH005");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^V100R006C00") {
  if (!patch || version_is_less(version: patch, test_version: "V100R006SPH005")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V100R006SPH005");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
