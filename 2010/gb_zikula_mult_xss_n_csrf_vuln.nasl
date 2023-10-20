# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zikula:zikula_application_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800773");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2010-1732", "CVE-2010-1724", "CVE-2010-4729");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Zikula Multiple XSS and CSRF Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_mandatory_keys("zikula/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39614");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/510988/100/0/threaded");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_vulnerability_in_zikula_application_framework.html");

  script_tag(name:"insight", value:"- Input passed to the 'lang' parameter and to the 'func' parameter in the
  'index.php' is not properly sanitised before being returned to the user.

  - Failure in the 'users' module to properly verify the source of HTTP request.

  - Error in 'authid protection' mechanism for lostpassword form and mailpasswd
  processing, which makes it easier for remote attackers to generate a flood of password requests.");

  script_tag(name:"solution", value:"Upgrade to the Zikula version 1.2.3 or later.");

  script_tag(name:"summary", value:"Zikula is prone to multiple cross-site scripting and cross-site request forgery vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to compromise the
  application, disclosure or modification of sensitive data, execute arbitrary
  HTML and script and conduct cross-site request forgery (CSRF) attacks.");

  script_tag(name:"affected", value:"Zikula version prior to 1.2.3");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit( 0 );

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"1.2.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.2.3", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);