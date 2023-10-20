# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113016");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-16 12:39:40 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND End of Life (EOL) Detection - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"The ISC BIND version on the remote host has reached
  the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of ISC BIND is not receiving
  any security updates from the vendor. Unfixed security vulnerabilities might be
  leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the ISC BIND version on the remote host to
  a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_xref(name:"URL", value:"https://www.isc.org/downloads/software-support-policy/");
  script_xref(name:"URL", value:"https://www.isc.org/downloads/");

  exit(0);
}

CPE = "cpe:/a:isc:bind";

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe: CPE) ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = build_eol_message( name: "ISC BIND",
                              cpe: CPE,
                              version: version,
                              location: location,
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );
  security_message( port: port, data: report, proto: proto );
  exit( 0 );
}

exit( 99 );
