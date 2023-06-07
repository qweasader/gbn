# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801778");
  script_version("2023-05-05T09:09:19+0000");
  script_cve_id("CVE-2011-1518");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");

  script_name("OTRS Multiple XSS Vulnerabilities (OSA-2011-01)");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in context of an affected
  site and steal cookie-based authentication credentials.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  by multiple scripts. A remote attacker could exploit this vulnerability using various parameters
  in a specially-crafted URL to execute script in a victim's Web browser within the security context
  of the hosting Web site.");

  script_tag(name:"solution", value:"Update to version 2.4.10, 3.0.7 or later.");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"affected", value:"OTRS versions 2.4.x prior to 2.4.10 and 3.x prior to 3.0.7.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2011-01-en/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44029");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66698");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47323");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.9") ||
   version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.10/3.0.7");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
