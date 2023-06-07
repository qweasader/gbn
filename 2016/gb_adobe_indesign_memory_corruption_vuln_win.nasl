###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe InDesign Memory Corruption Vulnerability (Windows)
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

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810242");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-7886");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-23 20:49:00 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-12-15 12:59:49 +0530 (Thu, 15 Dec 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe InDesign Memory Corruption Vulnerability (Windows)");

  script_tag(name:"summary", value:"Adobe InDesign is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified memory
  corruption error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected applications.");

  script_tag(name:"affected", value:"Adobe InDesign 11.4.1 and earlier
  versions on windows.");

  script_tag(name:"solution", value:"Upgrade to version 12.0.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb16-43.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94868");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

desVer = get_app_version(cpe:CPE);
if(!desVer){
  exit(0);
}

if(version_is_less(version:desVer, test_version:"12.0.0"))
{
  report = report_fixed_ver(installed_version:desVer, fixed_version:"12.0.0");
  security_message(data:report);
  exit(0);
}
