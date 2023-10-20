# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118254");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-11-01 11:45:13 +0100 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 11:27:00 +0000 (Thu, 28 Jul 2022)");

  script_cve_id("CVE-2016-2183");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.13, 3.4.x < 3.4.7, 3.5.x < 3.5.3 Sweet32 attack (bpo-27850) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a 'birthday attack' vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The DES and Triple DES ciphers, as used in the TLS, SSH, and
  IPSec protocols and other protocols and products, have a birthday bound of approximately four
  billion blocks, which makes it easier for remote attackers to obtain cleartext data via a
  birthday attack against a long-duration encrypted session, as demonstrated by an HTTPS session
  using Triple DES in CBC mode, aka a 'Sweet32' attack.");

  script_tag(name:"affected", value:"Python prior to version 2.7.13, versions 3.4.x prior to 3.4.7,
  and 3.5.x prior to 3.5.3.");

  script_tag(name:"solution", value:"Update to version 2.7.13, 3.4.7, 3.5.3 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/sweet32.html");
  script_xref(name:"Advisory-ID", value:"bpo-27850");

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

if( version_is_less( version:version, test_version:"2.7.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.4.0", test_version2:"3.4.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.5.0", test_version2:"3.5.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
