# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804201");
  script_version("2023-04-05T10:19:45+0000");
  script_cve_id("CVE-2012-3527", "CVE-2012-3528", "CVE-2012-3529",
                "CVE-2012-3530", "CVE-2012-3531");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2023-04-05 10:19:45 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2014-01-03 13:01:59 +0530 (Fri, 03 Jan 2014)");
  script_name("TYPO3 Multiple Vulnerabilities Aug12");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials or get sensitive information.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple errors exist in the application:

  - An error exists in backend help system, which misses a signature (HMAC) for a
parameter in the view_help.php file.

  - An error exists in the application, which fails to HTML-encode user input in
several places

  - An error exists in typo3 backend, which exposes Encryption Key when
configuration module is accessed.

  - An error exists in API method t3lib_div::RemoveXSS(), which fails to filter
specially crafted HTML injections.

  - An error exists in Install Tool, which fails to sanitize user input properly.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.19, 4.6.12, 4.7.4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"TYPO3 version 4.5.0 up to 4.5.18, 4.6.0 up to 4.6.11, 4.7.0 up to 4.7.3");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50287/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55052");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2012-004");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.18") ||
   version_in_range(version:vers, test_version:"4.6.0", test_version2:"4.6.11") ||
   version_in_range(version:vers, test_version:"4.7.0", test_version2:"4.7.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
