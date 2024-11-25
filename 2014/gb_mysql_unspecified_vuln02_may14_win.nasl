# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804575");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-2430", "CVE-2014-2431", "CVE-2014-2436", "CVE-2014-2440");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-08 13:14:08 +0530 (Thu, 08 May 2014)");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities - 02 (May 2014) - Windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors related
  to Performance Schema, Options, RBR.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate certain data
  and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Oracle MySQL version 5.5.36 and earlier and 5.6.16 and earlier on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57940");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66850");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66896");
  script_xref(name:"URL", value:"http://www.scaprepo.com/view.jsp?id=oval:org.secpod.oval:def:701638");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
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
  if(version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.36")||
     version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.16")) {
    security_message(port:port);
    exit(0);
  }
}
