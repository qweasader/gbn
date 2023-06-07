###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Jul 2014 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804689");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-4265", "CVE-2014-4219", "CVE-2014-4227");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-07-25 10:19:38 +0530 (Fri, 25 Jul 2014)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Jul 2014 (Windows)");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - Two unspecified errors related to the Deployment subcomponent.

  - An unspecified error in the Hotspot subcomponent related to bytecode
verification.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  or possibly other impacts.");

  script_tag(name:"affected", value:"Oracle  Java SE 6 update 75 and prior, 7 update 60 and prior, and 8 update 5.0
  and prior on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68603");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68620");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68632");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1030577");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[6-8]") {
  if(version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.75")||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.60")||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.5")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
