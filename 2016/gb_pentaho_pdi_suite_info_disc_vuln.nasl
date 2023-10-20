# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pentaho:data_integration";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808206");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-6940");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-24 10:37:42 +0530 (Tue, 24 May 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Pentaho Data Integration (PDI) Suite Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Pentaho PDI Suite is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to access the resources in the
  pentaho-solutions/system folder.");

  script_tag(name:"insight", value:"The flaw is due to the GetResource servlet,
  a vestige of the old platform UI, allows unauthenticated access to resources
  in the pentaho-solutions/system folder. Specifically vulnerable are properties
  files that may reveal passwords.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  unauthenticated access to properties files in the system solution
  which include properties files containing passwords.");

  script_tag(name:"affected", value:"4.3.x GA PDI - Suite
  4.4.x GA PDI - Suite
  5.0.x GA PDI - Suite
  5.1.x GA PDI - Suite
  5.2.x GA PDI - Suite.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133601");
  script_xref(name:"URL", value:"https://support.pentaho.com/hc/en-us/articles/205782329-Security-Vulnerability-Announcement-Feb-2015");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pentaho_ga_pdi_suite_remote_detect.nasl");
  script_mandatory_keys("Pentaho/PDI/Suite/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://support.pentaho.com/hc/en-us/articles/205782329-Security-Vulnerability-Announcement-Feb-2015");
  script_xref(name:"URL", value:"http://www.pentaho.com");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!penPort = get_app_port(cpe: CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:penPort)){
  exit(0);
}

if(dir == "/") dir = "";

## Create vulnerable url
url = dir + "/GetResource?resource=system/defaultUser.spring.properties";

if(http_vuln_check(port:penPort, url:url, check_header:TRUE,
                   pattern:"defaultAdminUserPassword=",
                   extra_check:"defaultNonAdminUserPassword="))
{
  report = http_report_vuln_url(port:penPort, url:url);
  security_message(port:penPort, data:report);
  exit(0);
}
exit(0);
