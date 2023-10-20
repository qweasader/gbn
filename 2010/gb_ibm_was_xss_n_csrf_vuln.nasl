# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801646");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-0783", "CVE-2010-0785");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("IBM WebSphere Application Server (WAS) XSS and CSRF Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42136");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44670");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Nov/1024686.html");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27004980");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross-site scripting
  and cross-site request forgery attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions 6.1 before 6.1.0.35 and
  7.0 before 7.0.0.13.");

  script_tag(name:"insight", value:"- A cross-site scripting vulnerability exists in the administrative console
  due to improper filtering on input values.

  - An input sanitation error in the administrative console can be exploited
  to conduct cross-site request forgery attacks.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply Fix Pack 7.0.0.13 and 6.1.0.35 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.12")||
   version_in_range(version:vers, test_version:"6.0", test_version2:"6.1.0.34")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.0.12/6.1.0.34");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);