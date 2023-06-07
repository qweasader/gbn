# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.147448");
  script_version("2022-05-30T09:32:02+0000");
  script_tag(name:"last_modification", value:"2022-05-30 09:32:02 +0000 (Mon, 30 May 2022)");
  script_tag(name:"creation_date", value:"2022-01-17 03:27:39 +0000 (Mon, 17 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-04 02:30:00 +0000 (Fri, 04 Feb 2022)");

  script_cve_id("CVE-2020-25717", "CVE-2020-21913", "CVE-2022-22989", "CVE-2022-22990", "CVE-2022-22991",
                "CVE-2022-22992", "CVE-2022-22993", "CVE-2022-22994", "CVE-2022-0194", "CVE-2022-23121",
                "CVE-2022-23122", "CVE-2022-23123", "CVE-2022-23124", "CVE-2022-23125", "CVE-2022-22995");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.0 < 5.19.117 Multiple Vulnerabilities (WDC-22002, WDC-22005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2020-25717: A flaw was discovered in the way Samba maps domain users to local users. An
  authenticated attacker could use this flaw to gain potential privilege escalation. Addressed this
  vulnerability by updating Debian (buster) version to 2:4.9.5+dfsg-5+deb10u2.

  - CVE-2020-21913: A use-after-free vulnerability was found in the International Components for
  Unicode (ICU) library which could result in denial of service or potentially the execution of
  arbitrary code. Addressed this vulnerability by updating the Debian (buster) version to
  63.1-6+deb10u2.

  - CVE-2022-22989: My Cloud OS 5 was vulnerable to a pre-authenticated stack overflow vulnerability
  on the FTP service. Addressed the vulnerability by adding defenses against stack overflow issues.

  - CVE-2022-22990, CVE-2022-22992, CVE-2022-22993: A limited authentication bypass vulnerability
  was discovered that could allow an attacker to achieve remote code execution and escalate
  privileges on the My Cloud devices. Addressed this vulnerability by changing access token
  validation logic and rewriting rule logic on PHP scripts.

  - CVE-2022-22991, CVE-2022-22994: A malicious user on the same LAN could use DNS spoofing followed
  by a command injection attack to trick a NAS device into loading through an unsecured HTTP call.
  Addressed this vulnerability by disabling checks for internet connectivity using HTTP.

  - CVE-2022-0194, CVE-2022-23121, CVE-2022-23122, CVE-2022-23123, CVE-2022-23124, CVE-2022-23125,
  CVE-2022-22995: Multiple critical vulnerabilities in Netatalk.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud
  EX4100, My Cloud EX2 Ultra, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100, My Cloud
  EX2100, My Cloud and WD Cloud with firmware versions prior to 5.19.117.");

  script_tag(name:"solution", value:"Update to firmware version 5.19.117 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-22002-my-cloud-os5-firmware-5-19-117");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-22005-netatalk-security-vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:wd_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.19.117")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.19.117");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
