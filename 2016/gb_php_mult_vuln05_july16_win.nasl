# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808633");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291",
                "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296",
                "CVE-2016-6297", "CVE-2016-6207", "CVE-2016-5399");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-07-29 11:54:44 +0530 (Fri, 29 Jul 2016)");
  script_name("PHP < 5.5.38, 5.6.x < 5.6.24, 7.0.x < 7.0.9 Multiple Vulnerabilities (Jul 2016) - Windows");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92111");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92074");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92097");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92073");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92115");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92099");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/24/2");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An integer overflow in the 'php_stream_zip_opener' function in 'ext/zip/zip_stream.c'

  - An integer signedness error in the 'simplestring_addn' function in 'simplestring.c' in
  xmlrpc-epi

  - 'ext/snmp/snmp.c' improperly interacts with the unserialize implementation and garbage
  collection

  - The 'locale_accept_from_http' function in 'ext/intl/locale/locale_methods.c' does not properly
  restrict calls to the ICU 'uloc_acceptLanguageFromHTTP' function

  - An error in the 'exif_process_user_comment' function of 'ext/exif/exif.c'

  - An error in the 'exif_process_IFD_in_MAKERNOTE' function of 'ext/exif/exif.c'

  - 'ext/session/session.c' does not properly maintain a certain hash data structure

  - An integer overflow in the 'virtual_file_ex' function of 'TSRM/tsrm_virtual_cwd.c'

  - An error in the 'php_url_parse_ex' function of 'ext/standard/url.c'

  - Integer overflow error within _gdContributionsAlloc()

  - Inadequate error handling in bzread()");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow attackers to cause a
  denial of service obtain sensitive information from process memory, or possibly have unspecified
  other impact.");

  script_tag(name:"affected", value:"PHP versions before 5.5.38, 5.6.x before 5.6.24 and 7.x before
  7.0.9.");

  script_tag(name:"solution", value:"Update to version 5.5.38, 5.6.24, 7.0.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(version_is_less(version:vers, test_version:"5.5.38")) {
  fix = "5.5.38";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.23")) {
  fix = "5.6.24";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.8")) {
  fix = "7.0.9";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
