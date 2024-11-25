# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900982");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-4040");

  script_name("phpMyFAQ GET Variable Cross-Site-Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  HTML and script code and cause cross-site scripting attacks.");

  script_tag(name:"affected", value:"phpMyFAQ prior to 2.0.17 and 2.5.0 prior to 2.5.2.");

  script_tag(name:"insight", value:"This vulnerability is caused because the application does not properly
  sanitize the input passed into 'GET' parameter in 'search.php'.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to phpMyFAQ 2.0.17 or 2.5.2");

  script_tag(name:"summary", value:"phpMyFAQ is prone to a cross-site scripting (XSS) vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37020");
  script_xref(name:"URL", value:"http://www.phpmyfaq.de/advisory_2009-09-01.php");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3241");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version,  test_version: "2.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.17");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version,  test_version: "2.5", test_version2: "2.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
