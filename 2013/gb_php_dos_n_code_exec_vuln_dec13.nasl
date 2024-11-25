# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804174");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2013-6420");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-12-19 18:09:47 +0530 (Thu, 19 Dec 2013)");
  script_name("PHP Remote Code Execution and Denial of Service Vulnerabilities (Dec 2013)");

  script_tag(name:"summary", value:"PHP is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to PHP version 5.3.28 or 5.4.23 or 5.5.7 or later.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within the 'asn1_time_to_time_t' function
  in 'ext/openssl/openssl.c' when parsing X.509 certificates.");

  script_tag(name:"affected", value:"PHP versions before 5.3.28, 5.4.x before 5.4.23, and 5.5.x before 5.5.7.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  or cause a denial of service (memory corruption).");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56055");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124436/PHP-openssl_x509_parse-Memory-Corruption.html");

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

if(version_is_less(version:vers, test_version:"5.3.28") ||
   version_in_range(version:vers, test_version:"5.4.0", test_version2:"5.4.22") ||
   version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.28/5.4.23/5.5.7");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
