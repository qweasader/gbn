# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805657");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2015-3329", "CVE-2015-3307", "CVE-2015-2783", "CVE-2015-1352",
                "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4602", "CVE-2015-4603",
                "CVE-2015-4604", "CVE-2015-4605", "CVE-2015-3411", "CVE-2015-3412");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2015-06-17 16:00:15 +0530 (Wed, 17 Jun 2015)");
  script_name("PHP Multiple Vulnerabilities - 03 (Jun 2015) - Linux");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple stack-based buffer overflows in the 'phar_set_inode' function in
    phar_internal.h script in PHP.

  - Vulnerabilities in 'phar_parse_metadata' and 'phar_parse_pharfile' functions
    in ext/phar/phar.c script in PHP.

  - A NULL pointer dereference flaw in the 'build_tablename' function in
    'ext/pgsql/pgsql.c' script that is triggered when handling NULL return values
    for 'token'.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service, to obtain sensitive
  information from process memory and to execute arbitrary code via crafted
  dimensions.");

  script_tag(name:"affected", value:"PHP versions before 5.4.40, 5.5.x before
  5.5.24, and 5.6.x before 5.6.8");

  script_tag(name:"solution", value:"Update to PHP 5.4.40 or 5.5.24 or 5.6.8
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74239");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75252");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75249");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75255");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75250");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=69085");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/01/4");

  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(vers =~ "^5\.5")
{
  if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.23"))
  {
    fix = "5.5.24";
    VULN = TRUE;
  }
}

if(vers =~ "^5\.6")
{
  if(version_in_range(version:vers, test_version:"5.6.0", test_version2:"5.6.7"))
  {
    fix = "5.6.8";
    VULN = TRUE;
  }
}

if(vers =~ "^5\.4")
{
  if(version_is_less(version:vers, test_version:"5.4.40"))
  {
    fix = "5.4.40";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = 'Installed Version: ' + vers + '\n' +
           'Fixed Version:     ' + fix + '\n';
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
