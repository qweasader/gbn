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
  script_oid("1.3.6.1.4.1.25623.1.0.143928");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-18 06:13:52 +0000 (Mon, 18 May 2020)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-25 15:10:00 +0000 (Wed, 25 May 2016)");

  script_cve_id("CVE-2016-4087");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Input Validation Vulnerability in Multiple Huawei Products (huawei-sa-20160427-01-dns)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an input validation vulnerability in Multiple Huawei products.");

  script_tag(name:"insight", value:"There is an input validation vulnerability in Multiple Huawei products, when the debug switch on the device is enabled, an attacker with network access may exploit this vulnerability by crafting malformed DNS packets and sending them to the target device. As for the lacking of input validation, an exploit could allow the attacker to cause a denial of service or remote code execution. (Vulnerability ID: HWPSIRT-2015-12046)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-4087.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a denial of service or remote code execution.");

  script_tag(name:"affected", value:"S12700 versions V200R005C00SPC300

S2700 versions V100R006C05

S3700 versions V100R006C05

S5700 versions V200R001C00 V200R002C00SPC100 V200R003C00SPC300 V200R005C00

S6700 versions V200R001C00 V200R002C00 V200R005C00 V200R005C01 V200R005C02

S7700 versions V200R001C00 V200R002C00 V200R003C00 V200R005C00

S9700 versions V200R001C00 V200R002C00 V200R003C00 V200R005C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20160427-01-dns-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s3700_firmware",
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
  if (version =~ "^V200R005C00SPC300") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s2700_firmware") {
  if (version =~ "^V100R006C05") {
    if (!patch || version_is_less(version: patch, test_version: "V100R006SPH026")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V100R006SPH026");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (cpe == "cpe:/o:huawei:s3700_firmware") {
  if (version =~ "^V100R006C05") {
    if (!patch || version_is_less(version: patch, test_version: "V100R006SPH026")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V100R006SPH026");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (cpe == "cpe:/o:huawei:s5700_firmware") {
  if (version =~ "^V200R001C00" || version =~ "^V200R002C00SPC100" || version =~ "^V200R003C00SPC300" ||
      version =~ "^V200R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH010")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V200R005SPH010");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (cpe == "cpe:/o:huawei:s6700_firmware") {
  if (version =~ "^V200R001C00" || version =~ "^V200R002C00" || version =~ "^V200R005C00" ||
      version =~ "^V200R005C01" || version =~ "^V200R005C02") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH010")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V200R005SPH010");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (cpe =~ "^cpe:/o:huawei:s[79]700_firmware") {
  if (version =~ "^V200R001C00" || version =~ "^V200R002C00" || version =~ "^V200R003C00" ||
      version =~ "^V200R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V200R008C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
