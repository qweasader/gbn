# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804200");
  script_version("2023-04-05T10:19:45+0000");
  script_cve_id("CVE-2012-3414");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2023-04-05 10:19:45 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2014-01-02 18:09:10 +0530 (Thu, 02 Jan 2014)");
  script_name("TYPO3 SWFUpload movieName Cross Site Scripting Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in swfupload.swf, which fails to validate the 'movieName'
parameter properly.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.17, 4.6.10, 4.7.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version 4.5.0 up to 4.5.16, 4.6.0 up to 4.6.9, 4.7.0 up to 4.7.1");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54245");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2012-003");
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

if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.16") ||
   version_in_range(version:vers, test_version:"4.6.0", test_version2:"4.6.9") ||
   version_in_range(version:vers, test_version:"4.7.0", test_version2:"4.7.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
