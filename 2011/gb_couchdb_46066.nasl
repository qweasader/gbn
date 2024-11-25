# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:couchdb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103053");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2011-02-02 13:26:27 +0100 (Wed, 02 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-3854");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB Web Administration Interface 0.8.x <= 1.0.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_apache_couchdb_http_detect.nasl");
  script_mandatory_keys("apache/couchdb/detected");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may let the
  attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Apache CouchDB version 0.8.0 through 1.0.1.");

  script_tag(name:"solution", value:"Update to version 1.0.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46066");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"0.8.0", test_version2:"1.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
