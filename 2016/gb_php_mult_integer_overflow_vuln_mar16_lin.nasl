# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807509");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2016-1904");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:33:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)");
  script_name("PHP Multiple Integer Overflow Vulnerabilities (Mar 2016) - Linux");

  script_tag(name:"summary", value:"PHP is prone to multiple integer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:
  multiple integer overflows in 'ext/standard/exec.c' script via a long string to
  the 'php_escape_shell_cmd' or 'php_escape_shell_arg' function.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service or possibly have unspecified
  other impact.");

  script_tag(name:"affected", value:"PHP versions 7.x before 7.0.2 on Linux");

  script_tag(name:"solution", value:"Update to PHP version 7.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=70976");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/81296");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/01/14/8");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^7\.0")
{
  if(version_is_less(version:vers, test_version:"7.0.2"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.2");
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
