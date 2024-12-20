# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113023");
  script_version("2024-03-15T15:36:48+0000");
  script_tag(name:"last_modification", value:"2024-03-15 15:36:48 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-10-16 14:52:53 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal End of Life (EOL) Detection - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"The Drupal version on the remote host has reached the End of
  Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of Drupal is not receiving any security updates
  from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise
  the security of this host.");

  script_tag(name:"solution", value:"Update the Drupal version on the remote host to a still
  supported version.");

  script_xref(name:"URL", value:"https://www.drupal.org/psa-2023-11-01"); # nb: Drupal 9 EOL notice
  script_xref(name:"URL", value:"https://www.drupal.org/psa-2023-06-07"); # nb: Drupal 7 final EOL extension to Jan 2025
  script_xref(name:"URL", value:"https://www.drupal.org/psa-2022-02-23"); # nb: Drupal 7 second EOL extension to Nov 2023
  script_xref(name:"URL", value:"https://www.drupal.org/psa-2021-11-30"); # nb: Drupal 8 EOL notice
  script_xref(name:"URL", value:"https://www.drupal.org/psa-2020-06-24"); # nb: Drupal 7 first EOL extension to Nov 2022
  script_xref(name:"URL", value:"https://www.drupal.org/psa-2019-02-25"); # nb: Initial Drupal 7 EOL notice for Nov 2021
  script_xref(name:"URL", value:"https://www.drupal.org/forum/general/news-and-announcements/2015-11-09/drupal-6-end-of-life-announcement");
  script_xref(name:"URL", value:"https://www.drupal.org/docs/understanding-drupal/understanding-drupal-version-numbers/legacy-drupal-release-history");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

# nb: Don't use a version_regex like [0-9]+\.[0-9]+ as the major release like 7 is enough here.
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version  = infos["version"];
location = infos["location"];

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = build_eol_message( name: "Drupal",
                              cpe: CPE,
                              version: version,
                              location: location,
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
