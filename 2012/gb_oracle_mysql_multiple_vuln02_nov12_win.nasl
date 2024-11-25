# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803112");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2012-3180", "CVE-2012-3177", "CVE-2012-3160");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-11-26 17:27:23 +0530 (Mon, 26 Nov 2012)");
  script_name("Oracle MySQL Server Multiple Vulnerabilities - 02 - (Nov 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51008/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56003");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56027");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/51008");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");
  script_xref(name:"URL", value:"https://support.oracle.com/rs?type=doc&id=1475188.1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to disclose potentially
  sensitive information, manipulate certain data and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Oracle MySQL version 5.1.x to 5.1.65 and
  Oracle MySQL version 5.5.x to 5.5.27 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors in MySQL server component
  related to server installation and server optimizer.");

  script_tag(name:"solution", value:"Apply the patch from the references or upgrade to latest version.");

  script_tag(name:"summary", value:"Oracle MySQL server is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

vers = eregmatch(pattern:"([0-9.a-z]+)", string:vers);
if(vers[1])
{
  if(version_in_range(version:vers[1], test_version:"5.1.0", test_version2:"5.1.65") ||
     version_in_range(version:vers[1], test_version:"5.5.0", test_version2:"5.5.27")){
    report = report_fixed_ver(installed_version:vers[1], fixed_version:"Apply the patch");
    security_message(data:report, port:port);
    exit(0);
  }
  exit(99);
}

exit(0);
