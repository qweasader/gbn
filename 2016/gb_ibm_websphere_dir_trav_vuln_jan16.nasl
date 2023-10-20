# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806823");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2012-3305");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-01-19 11:23:26 +0530 (Tue, 19 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server directory traversal vulnerability Jan16");

  script_tag(name:"summary", value:"IBM Websphere application server is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to

  - Improper validation of crafted files which will overwrites arbitrary files");

  script_tag(name:"impact", value:"Successful exploitation will leads to
  directory traversal attack.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  version 6.1 before 6.1.0.47, 7.0 before 7.0.0.25, 8.0 before 8.0.0.5,
  and 8.5 before 8.5.0.1");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) version 6.1.0.47, or 7.0.0.25, or 8.0.0.5, or 8.5.0.1, or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/77477");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55678");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21611313");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:wasVer, test_version:"6.1", test_version2:"6.1.0.46"))
{
  fix = "6.1.0.47";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.24"))
{
  fix = "7.0.0.25";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.3"))
{
  fix = "8.0.0.4";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.0.0"))
{
  fix = "8.5.0.1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver( installed_version:wasVer, fixed_version:fix );
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
