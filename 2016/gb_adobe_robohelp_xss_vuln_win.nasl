###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe RoboHelp Cross Site Scripting Vulnerability (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:adobe:robohelp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809840");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-7891");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 16:08:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-12-15 16:08:47 +0530 (Thu, 15 Dec 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe RoboHelp Cross Site Scripting Vulnerability (Windows)");

  script_tag(name:"summary", value:"Adobe RoboHelp server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper sanitization of
  user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  execute arbitrary script code in the context of the affected website. This may
  allow the attacker to steal cookie-based authentication credentials and to launch
  other attacks.");

  script_tag(name:"affected", value:"Adobe RoboHelp 11 and prior on Windows.");

  script_tag(name:"solution", value:"Apply the hotfix for Adobe RoboHelp from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/robohelp/apsb16-46.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94878");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_robohelp_detect_win.nasl");
  script_mandatory_keys("Adobe/RoboHelp/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!roboVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:roboVer, test_version:"11.0"))
{
  report = report_fixed_ver(installed_version:roboVer, fixed_version:"Apply the Hotfix");
  security_message(data:report);
  exit(0);
}
