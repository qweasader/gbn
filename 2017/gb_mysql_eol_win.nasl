# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108189");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-26 13:48:20 +0200 (Mon, 26 Jun 2017)");
  script_name("Oracle MySQL End of Life (EOL) Detection (Windows)");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.mysql.com/support/eol-notice.html");
  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/MySQL#Release_history");

  script_tag(name:"summary", value:"The Oracle MySQL version on the remote host has reached the End of Life (EOL) and
  should not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of Oracle MySQL is not receiving any security updates from
  the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the security of
  this host.");

  script_tag(name:"solution", value:"Update the Oracle MySQL version on the remote host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version  = infos["version"];
location = infos["location"];

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {
  report = build_eol_message( name:"Oracle MySQL",
                              cpe:CPE,
                              version:version,
                              location:location,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );