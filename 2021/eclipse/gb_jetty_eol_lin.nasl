# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117294");
  script_version("2024-09-13T15:40:36+0000");
  script_tag(name:"last_modification", value:"2024-09-13 15:40:36 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2021-04-08 09:18:25 +0000 (Thu, 08 Apr 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mort Bay / Eclipse Jetty End of Life (EOL) Detection - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://jetty.org/download.html#version-history");

  script_tag(name:"summary", value:"The Mort Bay / Eclipse Jetty version on the remote host has
  reached the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of Mort Bay / Eclipse Jetty is not receiving any
  security updates from the vendor. Unfixed security vulnerabilities might be leveraged by an
  attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Mort Bay / Eclipse Jetty version on the remote host
  to a still supported version.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

ver = infos["version"];

if( ret = product_reached_eol( cpe:CPE, version:ver ) ) {
  report = build_eol_message( name:"Mort Bay / Eclipse Jetty",
                              cpe:CPE,
                              version:ver,
                              location:infos["location"],
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
