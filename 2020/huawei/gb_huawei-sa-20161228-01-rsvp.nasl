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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143946");
  script_version("2021-08-05T02:01:00+0000");
  script_tag(name:"last_modification", value:"2021-08-05 02:01:00 +0000 (Thu, 05 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-20 04:52:42 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-26 15:23:00 +0000 (Mon, 26 Mar 2018)");

  script_cve_id("CVE-2016-8786");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: DoS Vulnerability in Multiple Huawei Devices (huawei-sa-20161228-01-rsvp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a denial of service (DoS) vulnerability in multiple Huawei devices.");

  script_tag(name:"insight", value:"There is a denial of service (DoS) vulnerability in multiple Huawei devices. Due to the lack of input validation, a remote attacker may craft a malformed Resource Reservation Protocol(RSVP) packet and send it to the device, causing a few buffer overflows and occasional device restart. (Vulnerability ID: HWPSIRT-2016-07017)Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to cause the device to restart occasionally.");

  script_tag(name:"affected", value:"S12700 versions V200R005C00 V200R006C00 V200R007C00 V200R008C00

S5700 versions V200R006C00 V200R007C00 V200R008C00

S6700 versions V200R008C00

S7700 versions V200R001C00 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00

S9700 versions V200R001C00 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161228-01-rsvp-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9700_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:s12700_firmware") {
  if (version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" ||
      version =~ "^V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s5700_firmware") {
  if (version =~ "^V200R006C00" || version =~ "^V200R007C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R008C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R008C00SPC500", fixed_patch: "V200R008SPH009");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s6700_firmware") {
  if (version =~ "^V200R008C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R008C00SPC500", fixed_patch: "V200R008SPH009");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s7700_firmware") {
  if (version =~ "^V200R001C00" || version =~ "^V200R002C00" || version =~ "^V200R003C00" ||
      version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s9700_firmware") {
  if (version =~ "^V200R001C00" || version =~ "^V200R002C00" || version =~ "^V200R003C00" ||
      version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
