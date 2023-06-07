# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103239");
  script_version("2023-05-26T09:09:36+0000");
  script_cve_id("CVE-1999-0501",
                "CVE-1999-0502",
                "CVE-1999-0507",
                "CVE-1999-0508",
                "CVE-2023-1944"); # nb: "root:root" as seen on https://github.com/kubernetes/minikube/compare/v1.29.0...v1.30.0#diff-7b41e58d929bdb16083790c3500e6f9aa19efb0976e6b65609b60396cd9ceeebL230
  script_tag(name:"last_modification", value:"2023-05-26 09:09:36 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2016-11-02 11:47:00 +0100 (Wed, 02 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SSH Brute Force Logins With Default Credentials Reporting");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_dependencies("default_ssh_credentials.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("default_ssh_credentials/started");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs to
  # choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd database.

  script_tag(name:"summary", value:"It was possible to login into the remote SSH server using
  default credentials.");

  script_tag(name:"vuldetect", value:"Reports default credentials detected by the VT
  'SSH Brute Force Logins With Default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108013).");

  script_tag(name:"insight", value:"As the VT 'SSH Brute Force Logins With Default Credentials'
  (OID: 1.3.6.1.4.1.25623.1.0.108013) might run into a timeout the actual reporting of this
  vulnerability takes place in this VT instead.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to e.g. gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

credentials = get_kb_list( "default_ssh_credentials/" + port + "/credentials" );
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
  c = get_kb_item( "default_ssh_credentials/" + port + "/too_many_logins" );
  if( c ) {
    report += '\nRemote host accept more than ' + c + ' logins. This could indicate some error or some "broken" device.\nScanner stops testing for default logins at this point.';
  }
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
