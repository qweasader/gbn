# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806883");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2015-2017");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:31 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server CRLF Injection Vulnerability Feb16");

  script_tag(name:"summary", value:"IBM Websphere application server is prone to CRLF injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an
  HTTP response splitting attack vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to use specially-crafted URL to cause the server to return a split
  response, once the URL is clicked. This would allow the attacker to perform
  further attacks, such as Web cache poisoning, cross-site scripting, and
  possibly obtain sensitive information.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  6.1 through 6.1.0.47, 7.0 before 7.0.0.39, 8.0 before 8.0.0.12,
  and 8.5 before 8.5.5.8.");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) 6.1.0.48, or 7.0.0.39, or 8.0.0.12, or 8.5.5.8");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21966837");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78457");

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

if(version_in_range(version:wasVer, test_version:"6.1", test_version2:"6.1.0.47"))
{
   fix = "6.1.0.48";
   VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.38"))
{
   fix = "7.0.0.39";
   VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.11"))
{
   fix = "8.0.0.12";
   VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.5.7"))
{
   fix = "8.5.5.8";
   VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
