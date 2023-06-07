###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Tivoli Storage Manager FastBack Server Multiple Buffer Overflow Vulnerabilities Aug16
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

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:tivoli_storage_manager_fastback";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808635");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-0212", "CVE-2016-0213", "CVE-2016-0216");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-03 19:35:00 +0000 (Thu, 03 Mar 2016)");
  script_tag(name:"creation_date", value:"2016-08-04 13:00:07 +0530 (Thu, 04 Aug 2016)");
  script_name("IBM Tivoli Storage Manager FastBack Server Multiple Buffer Overflow Vulnerabilities Aug16");

  script_tag(name:"summary", value:"IBM Tivoli Storage Manager FastBack is prone to multiple buffer overflow vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an improper bounds
  checking in server command processing.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to overflow a buffer and execute arbitrary code on the system with
  system privileges or cause the application to crash.");

  script_tag(name:"affected", value:"IBM Tivoli Storage Manager FastBack server
  version 5.5 and 6.1 through 6.1.11.1");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Storage Manager FastBack
  server version 6.1.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21975358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83280");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83281");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83278");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_ibm_tsm_fastback_detect.nasl");
  script_mandatory_keys("IBM/Tivoli/Storage/Manager/FastBack/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tivVer = get_app_version(cpe:CPE)){
  exit(0);
}

##For FastBack 5.5, IBM recommends upgrading to a fixed, supported version of FastBack (6.1.12).
if(version_is_equal(version:tivVer, test_version:"5.5") ||
   version_in_range(version:tivVer, test_version:"6.1.0", test_version2:"6.1.11.1"))
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:"6.1.12");
  security_message(data:report);
  exit(0);
}
