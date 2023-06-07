###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader Multiple Vulnerabilities - Aug07 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804266");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2007-0103");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-04-16 12:59:20 +0530 (Wed, 16 Apr 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities - Aug07 (Linux)");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exists due to unspecified error within Adobe PDF specification.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct denial of service,
memory corruption and execution of arbitrary code.");
  script_tag(name:"affected", value:"Adobe Reader before version 8.0 on Linux.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader 8.0 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/31364");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21910");
  script_xref(name:"URL", value:"http://projects.info-pull.com/moab/MOAB-06-01-2007.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"8.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.0");
  security_message(port:0, data:report);
  exit(0);
}
