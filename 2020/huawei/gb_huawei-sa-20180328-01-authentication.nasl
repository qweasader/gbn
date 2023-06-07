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
  script_oid("1.3.6.1.4.1.25623.1.0.107825");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-23 14:26:00 +0000 (Wed, 23 May 2018)");

  script_cve_id("CVE-2017-15327");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Improper Authorization Vulnerability on Huawei Switch Products (huawei-sa-20180328-01-authentication)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an improper authorization vulnerability on Huawei switch products.");

  script_tag(name:"insight", value:"There is an improper authorization vulnerability on Huawei switch products. The system incorrectly performs an authorization check when a normal user attempts to access certain information which is supposed to be accessed only by authenticated user. Successful exploit could cause information disclosure. (Vulnerability ID: HWPSIRT-2017-09010)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-15327.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit could cause information disclosure.");

  script_tag(name:"affected", value:"S12700 versions V200R005C00 V200R006C00 V200R006C01 V200R007C00 V200R007C01 V200R007C20 V200R008C00 V200R008C06 V200R009C00 V200R010C00

S7700 versions V200R001C00 V200R001C01 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R006C01 V200R007C00 V200R007C01 V200R008C00 V200R008C06 V200R009C00 V200R010C00

S9700 versions V200R001C00 V200R001C01 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R006C01 V200R007C00 V200R007C01 V200R008C00 V200R009C00 V200R010C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180328-01-authentication-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list("cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9700_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:s12700_firmware")  {
  if(version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R006C01" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C20" || version =~ "^V200R008C00" || version =~ "^V200R008C06" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH002")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH002");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s7700_firmware")  {
  if(version =~ "^V200R001C00" || version =~ "^V200R001C01" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R006C01" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C00" || version =~ "^V200R008C06" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH002")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH002");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9700_firmware")  {
  if(version =~ "^V200R001C00" || version =~ "^V200R001C01" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R006C01" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C00" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH002")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH002");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
