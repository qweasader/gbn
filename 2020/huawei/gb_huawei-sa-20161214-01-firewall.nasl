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
  script_oid("1.3.6.1.4.1.25623.1.0.143943");
  script_version("2021-08-03T11:00:50+0000");
  script_tag(name:"last_modification", value:"2021-08-03 11:00:50 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-20 04:01:31 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-05 23:57:00 +0000 (Wed, 05 Apr 2017)");

  script_cve_id("CVE-2016-8781");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: DoS Vulnerability in Huawei Firewall (huawei-sa-20161214-01-firewall)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a denial of service (DoS) vulnerability in Huawei firewalls due to no memory release after the execution of a specific command.");

  script_tag(name:"insight", value:"There is a denial of service (DoS) vulnerability in Huawei firewalls due to no memory release after the execution of a specific command. A remote attacker with specific permission can log in to a device and deliver a large number of such commands to exhaust memory, causing a DoS condition. (Vulnerability ID: HWPSIRT-2016-06075)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-8781.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit could exhaust system memory, causing a DoS condition.");

  script_tag(name:"affected", value:"Secospace USG6300 versions V500R001C20SPC200 V500R001C20SPC200PWE

Secospace USG6500 versions V500R001C20SPC200

Secospace USG6600 versions V500R001C20SPC200 V500R001C20SPC200PWE");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161214-01-firewall-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:usg6300_firmware") {
  if (version =~ "^V500R001C20") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C30SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V500R001C30SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V500R001C20SPC200PWE") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V500R001C20SPC300PWE");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg6500_firmware") {
  if (version =~ "^V500R001C20") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C30SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V500R001C30SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (cpe == "cpe:/o:huawei:usg6600_firmware") {
  if (version =~ "^V500R001C20") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C30SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V500R001C30SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V500R001C20SPC200PWE") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V500R001C20SPC300PWE");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
