# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113060");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-30 11:49:50 +0100 (Thu, 30 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cambium Networks Services Server Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cambium_networks_services_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cambium-networks/services-server/detected");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3526");

  script_tag(name:"summary", value:"Cambium Networks Services Server allows unauthenticated users to access sensitive
  files and directories.");

  script_tag(name:"vuldetect", value:"The script tries to access the critical files and directories.");

  script_tag(name:"insight", value:"Cambium Networks Services Server does not implement strict access control.
  This allows an unauthenticated attacker to access sensitive information, such as credentials.");

  script_tag(name:"impact", value:"The accessible files include user names and password hashes, potentially
  allowing an attacker to gain login credentials.");

  script_tag(name:"affected", value:"Cambium Networks Services Server prior to version 5.0.4.");

  script_tag(name:"solution", value:"Update to version 5.0.4 or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:cambium-networks:services-server";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = make_array( "/httpd.conf", "ServerRoot",
                    "/windows/apache2/conf/server.key", "BEGIN PRIVATE KEY",
                    "/windows/apache2/conf/server.pem", "BEGIN PRIVATE KEY",
                    "/windows/apache2/conf/httpd.conf", "ServerRoot",
                    "/stack/php/php.ini", "About php.ini",
                    "/windows/php/php.ini", "About php.ini",
                    "/stack/postgresql/data/ph_hba.conf", "PostgreSQL Client Authentication Configuration File",
                    "/stack/postgresql/data/postgresql.conf", "PostgreSQL configuration file",
                    "/logs", "Index of /logs",
                    "/scripts/cnss_test_users.sql", "INSERT INTO",
                    "/scripts/cnss_seed_users.sql", "INSERT INTO" );

file_list = ""; # nb: To make openvas-nasl-lint happy...

foreach file ( keys( files ) ) {
  res = http_get_cache( port: port, item: dir + file);

  if( res =~ "^HTTP/1\.[01] 200" && files[file] >< res ) {
    VULN = TRUE;
    file_list += file + '\r\n';
  }
}

if( VULN ) {
  report = 'It was possible to access the following sensitive files and directories:\r\n' + file_list;
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );