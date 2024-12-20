# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810883");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-3309", "CVE-2017-3308", "CVE-2017-3329", "CVE-2017-3456",
                "CVE-2017-3453", "CVE-2017-3600", "CVE-2017-3462", "CVE-2017-3463",
                "CVE-2017-3461", "CVE-2017-3464");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 16:32:00 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-04-19 16:44:58 +0530 (Wed, 19 Apr 2017)");
  script_name("Oracle Mysql Security Updates (apr2017-3236618) 02 - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in the 'Server: DML', 'Server: Optimizer',
  'Server: Thread Pooling', 'Client mysqldump', 'Server: Security: Privileges'
  components of the application.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to have impact on availability, confidentiality
  and integrity.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.5.54 and earlier,
  5.6.35 and earlier, 5.7.17 and earlier on Linux");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97763");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97831");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97776");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97818");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.54") ||
   version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.35") ||
   version_in_range(version:vers, test_version:"5.7", test_version2:"5.7.17"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);