# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118248");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-10-06 10:01:27 +0200 (Wed, 06 Oct 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:05:00 +0000 (Mon, 27 Jun 2022)");

  script_cve_id("CVE-2012-0876", "CVE-2016-0718", "CVE-2016-9063", "CVE-2017-9233");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.14, 3.3.x < 3.3.7, 3.4.x < 3.4.7, 3.5.x < 3.5.4, 3.6.x < 3.6.2 Expat 2.2.1 (bpo-30694) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"'Expat' in Python is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2012-0876: The XML parser (xmlparse.c) in expat computes hash values without restricting the
  ability to trigger hash collisions predictably, which allows context-dependent attackers to cause
  a denial of service (CPU consumption) via an XML file with many identifiers with the same value.

  - CVE-2016-0718: Expat allows context-dependent attackers to cause a denial of service (crash) or
  possibly execute arbitrary code via a malformed input document, which triggers a buffer overflow.

  - CVE-2016-9063: An integer overflow during the parsing of XML using the Expat library. This
  vulnerability affects Firefox < 50.

  - CVE-2017-9233: XML External Entity vulnerability in libexpat 2.2.0 and earlier (Expat XML Parser
  Library) allows attackers to put the parser in an infinite loop using a malformed external entity
  definition from an external DTD.");

  script_tag(name:"affected", value:"Python prior to version 2.7.14, versions 3.3.x prior to 3.3.7,
  3.4.x prior to 3.4.7, 3.5.x prior to 3.5.4 and 3.6.x prior to 3.6.2.");

  script_tag(name:"solution", value:"Update to version 2.7.14, 3.3.7, 3.4.7, 3.5.4, 3.6.2 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/expat-2.2.1.html");
  script_xref(name:"Advisory-ID", value:"bpo-30694");

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

if( version_is_less( version:version, test_version:"2.7.14" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.14", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.3.0", test_version2:"3.3.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.3.7", install_path:location);
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.4.0", test_version2:"3.4.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.5.0", test_version2:"3.5.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.6.0", test_version2:"3.6.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
