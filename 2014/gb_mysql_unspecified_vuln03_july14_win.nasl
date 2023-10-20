# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804723");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-2494", "CVE-2014-4207");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-24 17:29:02 +0530 (Thu, 24 Jul 2014)");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities-03 July14 (Windows)");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors related
to ENARC and SROPTZR.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate certain data
and cause a DoS (Denial of Service).");
  script_tag(name:"affected", value:"Oracle MySQL version 5.5.37 and earlier on Windows.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68593");
  script_xref(name:"URL", value:"http://www.computerworld.com/s/article/9249690/Oracle_to_release_115_security_patches");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixMSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(mysqlVer =~ "^(5\.5)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.37"))
  {
    report = report_fixed_ver(installed_version:mysqlVer, vulnerable_range:"5.5 - 5.5.37");
    security_message(port:sqlPort, data:report);
    exit(0);
  }
}
