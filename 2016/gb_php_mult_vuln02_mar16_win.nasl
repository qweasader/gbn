# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807090");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2015-8617", "CVE-2015-8616");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-10 01:29:00 +0000 (Sun, 10 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)");
  script_name("PHP Multiple Vulnerabilities - 02 (Mar 2016) - Windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An use-after-free vulnerability in the 'Collator::sortWithSortKeys' function
    in 'ext/intl/collator/collator_sort.c' script.

  - A format string vulnerability in the 'zend_throw_or_error' function in
    'Zend/zend_execute_API.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary code within the context of the affected
  application and to crash the affected application.");

  script_tag(name:"affected", value:"PHP version 7.0.0 on Windows");

  script_tag(name:"solution", value:"Update to PHP version 7.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79655");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79672");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=71105");

  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:vers, test_version:"7.0.0"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.0");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
