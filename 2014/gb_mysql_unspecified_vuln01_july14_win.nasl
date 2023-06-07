###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MySQL Multiple Unspecified vulnerabilities-01 July14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804721");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-4238", "CVE-2014-4240", "CVE-2014-4233",
                "CVE-2014-2484", "CVE-2014-4214");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-07-24 16:59:38 +0530 (Thu, 24 Jul 2014)");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities-01 July14 (Windows)");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors related
to SROPTZR, SRREP, SRFTS, and SRSP.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate certain data
and cause a DoS (Denial of Service).");
  script_tag(name:"affected", value:"Oracle MySQL version 5.6.17 and earlier on Windows");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68560");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68587");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68607");
  script_xref(name:"URL", value:"http://www.computerworld.com/s/article/9249690/Oracle_to_release_115_security_patches");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixMSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
  exit(0);
}

if(mysqlVer =~ "^(5\.6)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.17"))
  {
    report = report_fixed_ver(installed_version:mysqlVer, vulnerable_range:"5.6 - 5.6.17");
    security_message(port:sqlPort, data:report);
    exit(0);
  }
}
