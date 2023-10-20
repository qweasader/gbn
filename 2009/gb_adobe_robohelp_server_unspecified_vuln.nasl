# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801103");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3068");
  script_name("Adobe RoboHelp Server Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36245");
  script_xref(name:"URL", value:"http://www.intevydis.com/blog/?p=26");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36467");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa09-05.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2009/09/potential_robohelp_server_8_is.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_robohelp_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("adobe/robohelpserver/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute
  arbitrary code or compromise a vulnerable system.");

  script_tag(name:"affected", value:"Adobe RoboHelp Server version 8.0");

  script_tag(name:"insight", value:"The flaw is due to an unspecified 'pre-authentication' error
  which can be exploited via unknown vectors.");

  script_tag(name:"solution", value:"The vendor has released a patch to fix the issue, please see the references for more information.");

  script_tag(name:"summary", value:"Adobe RoboHelp Server is prone to an unspecified vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

robohelpPort = http_get_port(default:8080);

robohelpVer = get_kb_item("www/" + robohelpPort + "/RoboHelpServer");
robohelpVer = eregmatch(pattern:"^(.+) under (/.*)$", string:robohelpVer);

if(robohelpVer[1] != NULL)
{
  if(version_is_equal(version:robohelpVer[1], test_version:"8.0")){
    report = report_fixed_ver(installed_version:robohelpVer[1], vulnerable_range:"Equal to 8.0");
    security_message(port: robohelpPort, data: report);
    exit(0);
  }
}

exit(99);
