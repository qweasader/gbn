###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Oct 2014 (Linux)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108417");
  script_version("2022-05-19T11:50:09+0000");
  script_cve_id("CVE-2014-6527", "CVE-2014-6519", "CVE-2014-6476", "CVE-2014-6456");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-19 11:50:09 +0000 (Thu, 19 May 2022)");
  script_tag(name:"creation_date", value:"2014-10-20 13:23:18 +0530 (Mon, 20 Oct 2014)");

  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Oct 2014 (Linux)");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors within the Deployment subcomponent.

  - An error in the 'ClassFileParser::parse_classfile_bootstrap_methods_attribute'
    function in share/vm/classfile/classFileParser.cpp script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to manipulate certain data and execute arbitrary code.");

  script_tag(name:"affected", value:"Oracle Java SE 7 update 67 and prior, and 8
  update 20 and prior on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61609/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70522");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70531");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70560");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70570");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[78]") {
  if(version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.67")||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.20")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
