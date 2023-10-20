# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808136");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-2571", "CVE-2015-0505", "CVE-2015-0501", "CVE-2015-0499");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:M/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");

  script_tag(name:"creation_date", value:"2016-06-03 13:42:20 +0530 (Fri, 03 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-24 Jun16 (Linux)");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server
  component via unknown vectors related to Server : Optimizer, DDL,
  Server : Compiling, Server : Federated.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to cause a denial of service.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.5.42 and earlier,
  and 5.6.23 and earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74112");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74070");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74115");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:oracle:mysql";

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^5\.[56]")
{
  if(version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.42") ||
     version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.23"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);