# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804160");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2013-6712");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-12-06 13:02:20 +0530 (Fri, 06 Dec 2013)");
  script_name("PHP RCE Vulnerability");

  script_tag(name:"summary", value:"PHP is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to PHP version 5.5.8 or later.");

  script_tag(name:"insight", value:"The flaw is due to error in 'scan function' in
  'ext/date/lib/parse_iso_intervals.c' which does not validate user-supplied
  input when handling 'DateInterval' objects.");

  script_tag(name:"affected", value:"PHP versions 5.5.6 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to allow a remote attacker
  to cause a heap-based buffer overflow, resulting in a denial of service.");

  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=12fe4e90be7bfa2a763197079f68f5568a14e071");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.6")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.5.8");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
