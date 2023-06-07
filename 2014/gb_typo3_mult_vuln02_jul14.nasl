# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804465");
  script_version("2023-04-05T10:19:45+0000");
  script_cve_id("CVE-2014-3944", "CVE-2014-3946");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2023-04-05 10:19:45 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2014-07-03 13:22:50 +0530 (Thu, 03 Jul 2014)");
  script_name("TYPO3 Multiple Vulnerabilities-02 July-2104");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to:

  - An error in the authentication subcomponent that is triggered as the program
  fails to invalidate user's sessions that have timed out.

  - The program fails to honor user groups of logged in users when caching
  queries.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to easily gain access
to a users session and gain access to potentially sensitive information.");
  script_tag(name:"affected", value:"TYPO3 versions 6.2.0 to 6.2.2");
  script_tag(name:"solution", value:"Upgrade to TYPO3 6.2.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67624");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67629");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2014-001");
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

if(version_in_range(version:vers, test_version:"6.2.0", test_version2:"6.2.2")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"6.2.0 - 6.2.2", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
