###############################################################################
# OpenVAS Vulnerability Test
#
# Apple MacOSX Security Updates (HT208397)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812629");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2017-5753", "CVE-2017-5715");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-01-12 16:38:44 +0530 (Fri, 12 Jan 2018)");
  script_name("Apple MacOSX Security Updates (HT208397)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This security update includes security
  improvements to Safari and WebKit to mitigate the effects of Spectre
  (CVE-2017-5753 and CVE-2017-5715).");

  script_tag(name:"impact", value:"Successful exploitation will allow unauthorized
  disclosure of information to an attacker with local user access via a side-channel
  analysis of the data cache.");

  script_tag(name:"affected", value:"Apple Mac OS X 10.13.x through 10.13.2");

  script_tag(name:"solution", value:"Apply Apple Mac OS X 10.13.2 Supplemental
  Update. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102371");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102376");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

safVer = infos['version'];
path = infos['location'];

if(version_is_less(version:safVer, test_version:"11.0.2")) {
  report = report_fixed_ver( installed_version:safVer, fixed_version:"11.0.2", install_path:path );
  security_message(data:report);
  exit(0);
}

exit(99);