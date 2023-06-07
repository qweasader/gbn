# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108718");
  script_version("2023-04-17T10:19:34+0000");
  script_cve_id("CVE-1999-0501", "CVE-1999-0502", "CVE-1999-0507", "CVE-1999-0508",
                "CVE-2018-19063", "CVE-2018-19064");
  script_tag(name:"last_modification", value:"2023-04-17 10:19:34 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"creation_date", value:"2020-03-05 14:02:28 +0000 (Thu, 05 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FTP Brute Force Logins Reporting");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("gb_default_ftp_credentials.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("default_ftp_credentials/started");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs to
  # choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd database.

  script_tag(name:"summary", value:"It was possible to login into the remote FTP server using
  weak/known credentials.");

  script_tag(name:"vuldetect", value:"Reports weak/known credentials detected by the VT
  'FTP Brute Force Logins' (OID: 1.3.6.1.4.1.25623.1.0.108717).");

  script_tag(name:"insight", value:"As the VT 'FTP Brute Force Logins'
  (OID: 1.3.6.1.4.1.25623.1.0.108717) might run into a timeout the actual reporting of this
  vulnerability takes place in this VT instead.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to e.g. gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );

credentials = get_kb_list( "default_ftp_credentials/" + port + "/credentials" );
if( ! isnull( credentials ) ) {

  report = 'It was possible to login with the following credentials <User>:<Password>\n\n';

  # Sort to not report changes on delta reports if just the order is different
  credentials = sort( credentials );

  foreach credential( credentials ) {
    report += credential + '\n';
    vuln = TRUE;
  }
}

if( vuln ) {
  c = get_kb_item( "default_ftp_credentials/" + port + "/too_many_logins" );
  if( c ) {
    report += '\nRemote host accept more than ' + c + ' logins. This could indicate some error or some "broken" device.\nScanner stops testing for default logins at this point.';
  }
  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );
