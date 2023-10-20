# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812649");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-2573", "CVE-2017-3737", "CVE-2018-2696", "CVE-2018-2590",
                "CVE-2018-2583", "CVE-2018-2612", "CVE-2018-2645", "CVE-2018-2703",
                "CVE-2018-2647");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-28 01:29:00 +0000 (Wed, 28 Mar 2018)");
  script_tag(name:"creation_date", value:"2018-01-17 14:43:54 +0530 (Wed, 17 Jan 2018)");
  script_name("Oracle Mysql Security Updates (jan2018-3236628) 03 - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Multiple errors in the 'Server:Security:Privileges' component.

  - Multiple errors in the 'Server:Performance Schema' component.

  - An error in the 'Server:Replication' component.

  - An error in the 'Server:Packaging(OpenSSL)' component.

  - An error in the 'Server:GIS' component.

  - An error in the 'InnoDB' component.

  - An error in the 'Stored Procedure' component.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow remote attackers to conduct a denial-of-service condition, access and
  modify data.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.6.38 and earlier,
  5.7.20 and earlier on Linux");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(!infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE)){
  exit(0);
}

mysqlVer = infos['version'];
path = infos['location'];

if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.38")||
   version_in_range(version:mysqlVer, test_version:"5.7", test_version2:"5.7.20")){
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch", install_path:path);
  security_message(port:sqlPort, data:report);
  exit(0);
}

exit(99);
