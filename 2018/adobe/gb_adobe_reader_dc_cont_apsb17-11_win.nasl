###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader DC (Continuous Track) Security Updates (apsb17-11)-Windows
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812568");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2017-3011", "CVE-2017-3012", "CVE-2017-3013", "CVE-2017-3014",
                "CVE-2017-3015", "CVE-2017-3018", "CVE-2017-3019", "CVE-2017-3020",
                "CVE-2017-3021", "CVE-2017-3022", "CVE-2017-3024", "CVE-2017-3025",
                "CVE-2017-3026", "CVE-2017-3027", "CVE-2017-3028", "CVE-2017-3030",
                "CVE-2017-3031", "CVE-2017-3032", "CVE-2017-3033", "CVE-2017-3034",
                "CVE-2017-3036", "CVE-2017-3037", "CVE-2017-3038", "CVE-2017-3039",
                "CVE-2017-3040", "CVE-2017-3042", "CVE-2017-3043", "CVE-2017-3044",
                "CVE-2017-3045", "CVE-2017-3046", "CVE-2017-3048", "CVE-2017-3049",
                "CVE-2017-3050", "CVE-2017-3051", "CVE-2017-3052", "CVE-2017-3054",
                "CVE-2017-3055", "CVE-2017-3056", "CVE-2017-3057", "CVE-2017-3065",
                "CVE-2017-3035", "CVE-2017-3047", "CVE-2017-3017", "CVE-2017-3023",
                "CVE-2017-3041", "CVE-2017-3029", "CVE-2017-3053");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)");
  script_tag(name:"creation_date", value:"2018-03-12 13:58:05 +0530 (Mon, 12 Mar 2018)");
  script_name("Adobe Reader DC (Continuous Track) Security Updates (apsb17-11) - Windows");

  script_tag(name:"summary", value:"Adobe Reader DC (Continuous Track) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - use-after-free vulnerabilities.

  - heap buffer overflow vulnerabilities.

  - memory corruption vulnerabilities.

  - integer overflow vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code in the context of the user running the
  affected applications. Failed exploit attempts will likely cause a
  denial-of-service condition.");

  script_tag(name:"affected", value:"Adobe Reader DC (Continuous Track) 2015.023.20070 and earlier,
  Adobe Reader DC (Continuous Track) 2017.009.20043 and earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader DC (Continuous Track) version
  2017.009.20044  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-11.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Continuous/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

# 2017.009.20043 => 17.009.20043
# 2015.023.20070 => 15.023.20070
if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.009.20043") ||
   version_in_range(version:vers, test_version:"15.0", test_version2:"15.023.20070")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.009.20044 (2017.009.20044)", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);