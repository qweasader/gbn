# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108530");
  script_version("2023-10-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-01-18 14:38:04 +0100 (Fri, 18 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_name("SMTP Unencrypted Cleartext Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("smtpserver_detect.nasl", "gb_starttls_smtp.nasl");
  script_mandatory_keys("smtp/auth_methods/available");

  script_tag(name:"summary", value:"The remote host is running a SMTP server that allows cleartext logins over
  unencrypted connections.");

  script_tag(name:"impact", value:"An attacker can uncover login names and passwords by sniffing traffic to the
  SMTP server.");

  script_tag(name:"vuldetect", value:"Evaluates from previously collected info if a non SMTPS enabled SMTP server
  is providing the 'PLAIN' or 'LOGIN' authentication methods without sending the 'STARTTLS' command first.");

  script_tag(name:"solution", value:"Enable SMTPS or enforce the connection via the 'STARTTLS' command. Please see
  the manual of the SMTP server for more information.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = smtp_get_port( default:25 );

# SMTPS
encaps = get_port_transport( port );
if( encaps > ENCAPS_IP )
  exit( 99 );

auths = get_kb_list( "smtp/fingerprints/" + port + "/nontls_authlist" );
if( ! auths || ! is_array( auths ) )
  exit( 99 );

if( get_kb_item( "smtp/" + port + "/starttls" ) )
  STARTTLS = TRUE;

auth_report = ""; # nb: To make openvas-nasl-lint happy...

foreach auth( auths ) {
  if( auth == "LOGIN" || auth == "PLAIN" ) {
    VULN = TRUE;
    auth_report += '\n' + auth;
  }
}

if( VULN ) {
  report = 'The remote SMTP server accepts logins via the following cleartext authentication mechanisms over unencrypted connections:\n' + auth_report;
  if( STARTTLS )
    report += '\n\nThe remote SMTP server supports the \'STARTTLS\' command but isn\'t enforcing the use of it for the cleartext authentication mechanisms.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
