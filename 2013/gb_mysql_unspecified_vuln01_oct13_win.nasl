###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MySQL Multiple Unspecified vulnerabilities-01 Oct-2013 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804032");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-5767", "CVE-2013-5786", "CVE-2013-5793");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-10-28 15:46:59 +0530 (Mon, 28 Oct 2013)");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities-01 Oct-2013 (Windows)");


  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors related
to Optimizer and InnoDB.");
  script_tag(name:"affected", value:"Oracle MySQL version 5.6.12 and earlier on Windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose sensitive
information, manipulate certain data, cause a DoS (Denial of Service) and
bypass certain security restrictions.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55327");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63107");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63113");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63116");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.12"))
  {
    report = report_fixed_ver( installed_version:mysqlVer, fixed_version:"Apply the patch from the referenced advisory.");
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}
