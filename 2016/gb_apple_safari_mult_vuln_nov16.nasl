###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Multiple Vulnerabilities November16 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810207");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-1849", "CVE-2016-1858", "CVE-2016-1854", "CVE-2016-1855",
                "CVE-2016-1856", "CVE-2016-1857", "CVE-2016-1859");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 17:08:00 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-11-22 11:05:47 +0530 (Tue, 22 Nov 2016)");
  script_name("Apple Safari Multiple Vulnerabilities November16 (Mac OS X)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The 'Clear History and Website Data' feature mishandles the deletion of
    browsing history.

  - An insufficient taint tracking issue in the parsing of svg images.

  - Multiple memory corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to obtain sensitive information, remote attackers to execute arbitrary
  code or cause a denial of service.");

  script_tag(name:"affected", value:"Apple Safari versions before 9.1.1");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 9.1.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206565");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90690");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90689");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2016/May/msg00005.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"9.1.1"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"9.1.1");
  security_message(data:report);
  exit(0);
}
