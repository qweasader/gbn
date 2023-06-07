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
  script_oid("1.3.6.1.4.1.25623.1.0.112759");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-26 13:51:00 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-05 18:49:00 +0000 (Wed, 05 Jun 2019)");

  script_cve_id("CVE-2019-5300");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Digital Signature Verification Bypass Vulnerability in Some Huawei AR Products (huawei-sa-20190320-01-ar)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a digital signature verification bypass vulnerability in some Huawei AR products.");

  script_tag(name:"insight", value:"There is a digital signature verification bypass vulnerability in some Huawei AR products. The vulnerability is due to the affected software improperly verifying digital signatures for the software image in the affected device. A local attacker with high privilege may exploit the vulnerability to bypass integrity checks for software images and install a malicious software image on the affected device. (Vulnerability ID: HWPSIRT-2019-01058)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5300.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to bypass integrity checks for software images and install a malicious software image on the affected device.");

  script_tag(name:"affected", value:"AR1200 versions V200R007C00SPC600 V200R008C20SPC800 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

AR1200-S versions V200R007C00SPC600 V200R008C20SPC800 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

AR150 versions V200R007C00SPC600 V200R008C20SPC800 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

AR160 versions V200R007C00SPC600 V200R008C20SPC800 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

AR200 versions V200R007C00SPC600 V200R008C20SPC800 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

AR2200 versions V200R007C00SPC600 V200R008C20SPC800 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

AR2200-S versions V200R007C00SPC600 V200R008C20SPC800 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

AR3200 versions V200R007C00SPC600 V200R008C20SPC800 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

AR3600 versions V200R008C50SPC500 V200R009C00SPC500 V200R008C50 V200R009C00

SRG1300 versions V200R007C00SPC600 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

SRG2300 versions V200R007C00SPC600 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200

SRG3300 versions V200R007C00SPC600 V200R008C50SPC500 V200R009C00SPC500 V200R010C00SPC200");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190320-01-ar-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar1200-s_firmware",
                     "cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar2200-s_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar3600_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200-s_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar160_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200-s_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3600_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R008C50" || version =~ "^V200R009C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009SPH017")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009SPH017");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg1300_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg2300_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg3300_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
