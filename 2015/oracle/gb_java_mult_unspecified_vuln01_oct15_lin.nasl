###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Oct 2015 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.108396");
  script_version("2022-05-19T11:50:09+0000");
  script_cve_id("CVE-2015-4916", "CVE-2015-4908", "CVE-2015-4906", "CVE-2015-4901",
                "CVE-2015-4868");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-19 11:50:09 +0000 (Thu, 19 May 2022)");
  script_tag(name:"creation_date", value:"2015-10-27 11:40:31 +0530 (Tue, 27 Oct 2015)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Oct 2015 (Linux)");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability via unknown
  vectors.");

  script_tag(name:"affected", value:"Oracle Java SE 8 update 60 and prior
  on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/alerts-086861.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77221");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77223");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77214");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77226");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77225");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(vers =~ "^(1\.8)")
{
  if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.60"))
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     ' + "Apply the patch"  + '\n';
    security_message(data:report);
    exit(0);
  }
}

exit(99);