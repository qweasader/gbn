# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812177");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-4910", "CVE-2015-4890", "CVE-2015-4862", "CVE-2015-4800",
                "CVE-2015-4791");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-11-22 15:09:17 +0530 (Wed, 22 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-05 (Oct 2015) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors exist in the MySQL Server
  component via unknown vectors related to Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to affect confidentiality, integrity, and
  availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.6.26 and earlier
  on windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77147");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE)) exit(0);
mysqlVer = infos['version'];
mysqlPath = infos['location'];

if(mysqlVer =~ "^(5\.6)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.26"))
  {
    report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch", install_path:mysqlPath);
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}
