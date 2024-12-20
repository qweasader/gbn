# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105935");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-09 16:55:49 +0700 (Tue, 09 Dec 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-9015");

  script_name("Drupal Session Hijacking Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_mandatory_keys("drupal/detected");

  script_tag(name:"summary", value:"Drupal is vulnerable to session hijacking.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A special crafted request can give a user access to another
  user's session, allowing an attacker to hijack a random session.");

  script_tag(name:"impact", value:"An attacker may gain unauthorized access to the application.");

  script_tag(name:"affected", value:"Drupal 6.x versions prior to 6.34. Drupal 7.x versions prior to 7.34.");

  script_tag(name:"solution", value:"Upgrade to Drupal 6.34, 7.34 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2014-006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71195");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"6.34")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.34", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

if(version =~ "^7\.") {
  if(version_is_less(version:version, test_version:"7.34")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"7.34", install_path:location);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);