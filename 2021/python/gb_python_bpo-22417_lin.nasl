# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118257");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-11-01 11:45:13 +0100 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2014-9365");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.9, 3.4.x < 3.4.3 Validate TLS certificate (bpo-22417) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a man-in-the-middle vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The HTTP clients in the httplib, urllib, urllib2, and xmlrpclib
  libraries in CPython (aka Python), when accessing an HTTPS URL, do not check the certificate
  against a trust store or verify that the server hostname matches a domain name in the subject's
  Common Name or subjectAltName field of the X.509 certificate, which allows man-in-the-middle
  attackers to spoof SSL servers via an arbitrary valid certificate.");

  script_tag(name:"affected", value:"Python prior to version 2.7.9 and versions 3.x prior to 3.4.3.");

  script_tag(name:"solution", value:"Update to version 2.7.9, 3.4.3 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/validate-tls-certificate.html");
  script_xref(name:"Advisory-ID", value:"bpo-22417");

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

if( version_is_less( version:version, test_version:"2.7.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.0", test_version2:"3.4.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
