# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810955");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-4473");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-16 12:47:00 +0000 (Fri, 16 Jun 2017)");
  script_tag(name:"creation_date", value:"2017-06-20 15:46:19 +0530 (Tue, 20 Jun 2017)");
  script_name("PHP Remote Code Execution Vulnerability-01 (Jun 2017) - Windows");

  script_tag(name:"summary", value:"PHP is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  '/ext/phar/phar_object.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary code in the context of the user running
  the affected application. Failed exploit attempts will likely cause a
  denial-of-service condition.");

  script_tag(name:"affected", value:"PHP versions 7.0.7 and 5.6.x on Windows");

  script_tag(name:"solution", value:"Update to PHP version 7.0.8 or 5.6.23
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1347772");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98999");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2016-10/msg00007.html");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^5\.6")
{
  if(version_is_less(version:vers, test_version:"5.6.23")){
    fix = '5.6.23';
  }
}

else if(vers =~ "^7\.0")
{
  if(version_is_less(version:vers, test_version:"7.0.8")){
    fix = '7.0.8';
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
