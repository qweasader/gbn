# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814260");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-3186", "CVE-2018-3195", "CVE-2018-3170", "CVE-2018-3279",
                "CVE-2018-3137", "CVE-2018-3286", "CVE-2018-3285", "CVE-2018-3280",
                "CVE-2018-3182", "CVE-2018-3203", "CVE-2018-3145", "CVE-2018-3212");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-31 13:24:00 +0000 (Wed, 31 May 2023)");
  script_tag(name:"creation_date", value:"2018-10-17 11:12:23 +0530 (Wed, 17 Oct 2018)");
  script_name("Oracle Mysql Security Update (cpuoct2018 - 03) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2018.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuoct2018");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An unspecified error within 'Server: DML' component of MySQL Server.

  - Multiple unspecified errors within 'Server: Optimizer' component of MySQL
    Server.

  - An unspecified error within 'Server: Parser' component of MySQL Server.

  - Multiple unspecified errors within 'Server: DDL' component of MySQL Server.

  - An unspecified error within 'Server: Information Schema' component of MySQL
    Server.

  - An unspecified error within 'Server: JSON' component of MySQL Server.

  - An unspecified error within 'Server: Security: Roles' component of MySQL Server.

  - An unspecified error within 'Server: Windows' component of MySQL Server.

  - An unspecified error within 'Server: Security: Privileges' component of MySQL
    Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to have an
  impact on integrity and availability.");

  script_tag(name:"affected", value:"Oracle MySQL version 8.0.x through 8.0.12.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"8.0", test_version2:"8.0.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See reference", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
