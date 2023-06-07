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
  script_oid("1.3.6.1.4.1.25623.1.0.143984");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-27 04:19:46 +0000 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-26 15:21:00 +0000 (Mon, 26 Feb 2018)");

  script_cve_id("CVE-2017-17166");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Resource Exhaustion Vulnerability on Several Products (huawei-sa-20171213-02-h323)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a resource exhaustion vulnerability on several products.");

  script_tag(name:"insight", value:"There is a resource exhaustion vulnerability on several products. The software does not process certain field of H.323 message properly, a remote unauthenticated attacker could send crafted H.323 message to the device, successful exploit could cause certain service unavailable since the stack memory is exhausted. (Vulnerability ID: HWPSIRT-2017-02042)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17166.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit could cause certain service unavailable since the stack memory is exhausted.");

  script_tag(name:"affected", value:"DP300 versions V500R002C00

IPS Module versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C30 V500R001C30SPC100

NIP6300 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C30 V500R001C30SPC100

NIP6600 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C30SPC100

Secospace USG6300 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C30 V500R001C30SPC100

Secospace USG6500 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C30 V500R001C30SPC100

Secospace USG6600 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

TE60 versions V600R006C00

TP3206 versions V100R002C00

VP9660 versions V500R002C00 V500R002C00SPC001T V500R002C00SPC200 V500R002C00SPC200T V500R002C00SPC201T V500R002C00SPC203T V500R002C00SPC204T V500R002C00SPC205T V500R002C00SPC206T V500R002C00SPC300 V500R002C00SPC400 V500R002C00SPC500 V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC800 V500R002C00SPC900 V500R002C00SPC900T V500R002C00SPC901T V500R002C00SPCa00 V500R002C00SPCb00 V500R002C00SPCb01T V500R002C00SPCc00 V500R002C00T V500R002C10 V500R002C10T

ViewPoint 8660 versions V100R008C03B013SP02 V100R008C03B013SP03 V100R008C03B013SP04 V100R008C03SPC100 V100R008C03SPC100B010 V100R008C03SPC100B011 V100R008C03SPC200 V100R008C03SPC200T V100R008C03SPC300 V100R008C03SPC400 V100R008C03SPC500 V100R008C03SPC600 V100R008C03SPC600T V100R008C03SPC700 V100R008C03SPC800 V100R008C03SPC900 V100R008C03SPCa00 V100R008C03SPCb00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-02-h323-en");

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

if (cpe =~ "^cpe:/o:huawei:usg6[35]00_firmware") {
  if (version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" ||
      version =~ "^V500R001C50") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V500R001C60");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg6600_firmware") {
  if (version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" ||
      version =~ "^V500R001C50") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V500R001C60SPC100");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
