# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808130");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-0427", "CVE-2014-0430", "CVE-2014-0433",
                "CVE-2013-5882", "CVE-2013-5894");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-06-03 13:42:32 +0530 (Fri, 03 Jun 2016)");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities - 18 (Jun 2016) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL
  Server component via unknown vectors related to FTS, Performance Schema,
  Thread Pooling, Stored Procedures, and InnoDB.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to manipulate certain data and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Oracle MySQL version 5.6.13 and
  earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56491");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64868");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64873");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^5\.6" && version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.13")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"5.6 - 5.6.13");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
