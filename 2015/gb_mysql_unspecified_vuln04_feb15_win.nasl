# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805135");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-0391");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-02-03 12:59:47 +0530 (Tue, 03 Feb 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities-04 (Feb 2015) - Windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server
  component via unknown vectors related to DLL.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information, manipulate certain data,
  cause a DoS (Denial of Service), and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 5.5.38 and
  earlier, and 5.6.19 and earlier on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62525");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72205");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

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

if(vers =~ "^5\.[56]") {
  if(version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.38")||
     version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.19")) {
    report = 'Installed version: ' + vers + '\n';
    security_message(data:report, port:port);
    exit(0);
  }
}
