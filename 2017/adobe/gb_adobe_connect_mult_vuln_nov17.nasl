###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Connect Multiple Vulnerabilities Nov17
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812212");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-11291", "CVE-2017-11287", "CVE-2017-11288", "CVE-2017-11289",
                "CVE-2017-11290");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-14 14:57:00 +0000 (Thu, 14 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-11-16 12:45:11 +0530 (Thu, 16 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Multiple Vulnerabilities Nov17");

  script_tag(name:"summary", value:"Adobe Connect is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple input validation errors.

  - A critical Server-Side Request Forgery error.

  - An UI redressing error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass network access controls, execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site
  and conduct clickjacking attacks.");

  script_tag(name:"affected", value:"Adobe Connect versions 9.6.2 and earlier");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb17-35.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101838");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location( cpe:CPE, port:acPort, exit_no_version:TRUE)) exit(0);
acVer = infos['version'];
dir = infos['location'];

if(version_is_less(version:acVer, test_version:"9.7"))
{
  report = report_fixed_ver(installed_version:acVer, fixed_version:"9.7", install_path:dir);
  security_message(data:report, port:acPort);
  exit(0);
}
exit(0);
