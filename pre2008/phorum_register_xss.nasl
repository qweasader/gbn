# SPDX-FileCopyrightText: 2006 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phorum:phorum";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19584");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2005-2836");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Phorum < 5.0.18 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2006 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_phorum_http_detect.nasl");
  script_mandatory_keys("phorum/detected");

  script_tag(name:"summary", value:"Phorum contains a script called 'register.php' which is
  vulnerable to a cross-site scripting (XSS) attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may exploit this problem to steal the authentication
  credentials of third party users.");

  script_tag(name:"solution", value:"Update to version 5.0.18 or later.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-09/0018.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14726");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
