# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118224");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-09-21 14:37:57 +0200 (Tue, 21 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");

  script_cve_id("CVE-2016-5699");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.10, 3.x < 3.3.7, 3.4.x < 3.4.4 HTTP Header Injection Vulnerability (bpo-22928) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/mac-os-x/detected");

  script_tag(name:"summary", value:"Python is prone to a HTTP header injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A CRLF injection vulnerability in the 'HTTPConnection.putheader'
  function in urllib2 and urllib in CPython (aka Python) allows remote attackers to inject arbitrary
  HTTP headers via CRLF sequences in a URL.");

  script_tag(name:"affected", value:"Python versions prior to 2.7.10, 3.x prior to 3.3.7 and
  3.4.x prior to 3.4.4.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/http-header-injection.html");
  script_xref(name:"Advisory-ID", value:"bpo-22928");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.7.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.0", test_version2:"3.3.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.3.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.4.0", test_version2:"3.4.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
