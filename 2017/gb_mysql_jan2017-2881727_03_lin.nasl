# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809868");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2016-8318", "CVE-2016-8327", "CVE-2017-3273", "CVE-2017-3257");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-22 15:01:00 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2017-01-18 18:37:18 +0530 (Wed, 18 Jan 2017)");
  script_name("Oracle Mysql Security Updates (jan2017-2881727) 03 - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to: multiple
  unspecified errors in sub components 'Security: Encryption', 'DDL',
  'InnoDB' and 'Replication'.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote to have an impact on availability,
  confidentiality and integrity.");

  script_tag(name:"affected", value:"Oracle MySQL version
  5.6.34 and earlier, 5.7.16 and earlier, on Linux");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95557");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95583");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95589");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(mysqlVer =~ "^(5\.)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.34") ||
     version_in_range(version:mysqlVer, test_version:"5.7", test_version2:"5.7.16"))
  {
    report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch");
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}
