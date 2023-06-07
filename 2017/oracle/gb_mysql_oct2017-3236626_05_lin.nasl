###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Mysql Security Updates (oct2017-3236626) 05 - Linux
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811994");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-10283", "CVE-2017-10294", "CVE-2017-10286", "CVE-2017-10155",
                "CVE-2017-10314", "CVE-2017-10276", "CVE-2017-10227");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-14 02:29:00 +0000 (Thu, 14 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-10-18 12:58:45 +0530 (Wed, 18 Oct 2017)");
  script_name("Oracle Mysql Security Updates (oct2017-3236626) 05 - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in 'Server: Performance Schema' component.

  - An error in 'Server: Optimizer' component.

  - An error in 'Server: InnoDB' component.

  - An error in 'Server: Pluggable Auth' component.

  - An error in 'Server: Memcached' component.

  - An error in 'Server: FTS' component.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to compromise availability
  integrity and confidentiality of the system.");

  script_tag(name:"affected", value:"Oracle MySQL version
  5.6.37 and earlier, 5.7.19 and earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101444");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101314");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101441");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101337");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
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

if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.37") ||
   version_in_range(version:mysqlVer, test_version:"5.7", test_version2:"5.7.19"))
{
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch");
  security_message(data:report, port:sqlPort);
  exit(0);
}
