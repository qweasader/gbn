# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811985");
  script_version("2024-02-29T14:37:57+0000");
  script_cve_id("CVE-2017-10296", "CVE-2017-10365", "CVE-2017-10284");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-29 14:37:57 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-05 14:26:00 +0000 (Fri, 05 Aug 2022)");
  script_tag(name:"creation_date", value:"2017-10-18 12:54:54 +0530 (Wed, 18 Oct 2017)");
  script_name("Oracle Mysql Security Updates (oct2017-3236626) 01 - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple uspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An unspecified vulnerability in 'Server: DML'.

  - An unspecified vulnerability in 'Server: InnoDB'.

  - An unspecified vulnerability in 'Server: Stored Procedure'");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to compromise confidentiality integrity
  and availability of the system.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.7.18 and earlier on Linux");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101373");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101385");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"5.7", test_version2:"5.7.18")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply the patch");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
