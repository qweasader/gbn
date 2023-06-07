###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Domino Server Stack Buffer Overflow Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107155");
  script_version("2022-04-13T11:57:07+0000");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-04-26 07:07:25 +0200 (Wed, 26 Apr 2017)");

  script_cve_id("CVE-2017-1274");

  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-10 17:29:00 +0000 (Fri, 10 May 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("IBM Lotus Domino Server Stack Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"IBM Lotus Domino Server is prone to a stack-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IBM Domino is vulnerable to a stack-based buffer overflow, caused by improper
  bounds checking when parsing BMP images.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the context
  of the affected application. Failed exploit attempts will likely cause a denial-of-service condition.");

  script_tag(name:"affected", value:"IBM Domino 9.0.1 Fix Pack 3 (plus Interim Fixes) and earlier.
  IBM Domino 8.5.3 Fix Pack 6 (plus Interim Fixes) and earlier All 9.0 and 8.5.x releases of IBM Domino prior to
  those listed above.");

  script_tag(name:"solution", value:"Domino 9.0.x users should update to Domino 9.0.1 Fix Pack 3 Interim Fix 3.
  Domino 8.5.x users should update to Domino 8.5.3 Fix Pack 6 Interim Fix 7.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97910");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"9.0", test_version2:"9.0.1.3")){
  fix = "9.0.1 FP3 IF3";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.3.6")){
  fix = "8.5.3 FP6 IF7";
  VULN = TRUE;
}

if(VULN){
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
