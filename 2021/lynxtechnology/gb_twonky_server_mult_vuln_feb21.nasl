# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:twonky:twonky_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117235");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2021-03-01 13:35:36 +0000 (Mon, 01 Mar 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Twonky Server < 8.5.2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_twonky_server_detect.nasl");
  script_mandatory_keys("twonky/server/detected");

  script_xref(name:"URL", value:"https://docs.twonky.com/display/TRN/Twonky+Server+8.5.2");

  script_tag(name:"summary", value:"Twonky Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target system.");

  script_tag(name:"insight", value:"The update fixed:

  - password obfuscation

  - RPC

  security issues. No further details were provided by the vendor.");

  script_tag(name:"affected", value:"Twonky Server versions prior to 8.5.2.");

  script_tag(name:"solution", value:"Update to version 8.5.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"8.5.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.5.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
