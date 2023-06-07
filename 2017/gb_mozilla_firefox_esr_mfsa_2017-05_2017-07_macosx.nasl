###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Security Updates(mfsa_2017-05_2017-07)-MAC OS X
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809899");
  script_version("2021-10-12T09:28:32+0000");
  script_cve_id("CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5404",
                "CVE-2017-5407", "CVE-2017-5410", "CVE-2017-5398", "CVE-2017-5408",
                "CVE-2017-5405");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-12 09:28:32 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-03-08 11:16:50 +0530 (Wed, 08 Mar 2017)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2017-05_2017-07)-MAC OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The asm.js JIT-spray bypass of ASLR and DEP.

  - The memory Corruption when handling ErrorResult.

  - An use-after-free working with events in FontFace objects.

  - An use-after-free working with ranges in selections.

  - The pixel and history stealing via floating-point timing side channel with SVG filters.

  - The memory corruption during JavaScript garbage collection incremental sweeping.

  - The file deletion via callback parameter in Mozilla Windows Updater and Maintenance Service.

  - The cross-origin reading of video captions in violation of CORS.

  - The FTP response codes can cause use of uninitialized values for ports.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote to
  execute arbitrary code, to delete arbitrary files by leveraging certain local
  file execution, to obtain sensitive information, and to cause a denial of
  service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 45.8 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR 45.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-06");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"45.8"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"45.8");
  security_message(data:report);
  exit(0);
}
