# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808121");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2014-2494", "CVE-2014-4207");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-03 13:42:45 +0530 (Fri, 03 Jun 2016)");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-09 Jun16 (Linux)");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL
  Server component via unknown vectors related to ENARC and SROPTZR.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to manipulate certain data and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Oracle MySQL version 5.5.37 and
  earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68593");
  script_xref(name:"URL", value:"http://www.computerworld.com/s/article/9249690/Oracle_to_release_115_security_patches");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixMSQL");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^5\.5" && version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.37")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"5.5 - 5.5.37");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
