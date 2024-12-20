# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100170");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_cve_id("CVE-2009-1576");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Drupal HTML Injection and Information Disclosure Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_mandatory_keys("drupal/detected");

  script_tag(name:"summary", value:"Drupal is prone to a cross-site scripting vulnerability and an
  information-disclosure vulnerability.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to obtain potentially
  sensitive information, execute arbitrary script code in the browser of an unsuspecting user in
  the context of the affected site, steal cookie-based authentication credentials, or control how
  the site is rendered to the user. Other attacks are also possible.");

  script_tag(name:"affected", value:"Drupal 5.x (prior to 5.17)

  Drupal 6.x (prior to 6.11)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34779");
  script_xref(name:"URL", value:"http://drupal.org/node/449078");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 5.17/6.10 or later.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"5", test_version2:"5.16") ||
   version_in_range(version:version, test_version:"6", test_version2:"6.10")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.17/6.10", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);