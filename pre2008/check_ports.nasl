# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Services known to crash or freeze on a port scan:
#
# ClearCase (TCP/371)
# NetBackup

# References
#
# From: marek.rouchal@infineon.com
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org,
#   submissions@packetstormsecurity.org
# CC: rheinold@rational.com, buggy@segmentationfault.de,
#    Thorsten.Delbrouck@guardeonic.com, manfred.korger@infineon.com
# Date: Fri, 22 Nov 2002 10:30:11 +0100
# Subject: ClearCase DoS vulnerability

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10919");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Check open ports");
  # nb: Needs to run at the end of the scan because of the required info only available in this phase...
  script_category(ACT_END);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("General");
  script_dependencies("secpod_open_tcp_ports.nasl");
  script_mandatory_keys("TCP/PORTS");

  script_tag(name:"summary", value:"This plugin checks if the port scanners did not kill a service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

ports = get_kb_list( "TCP/PORTS" );
if( isnull( ports ) ) exit( 0 );

at_least_one = 0;
number_of_ports = 0;
report = make_list();
timeouts = 0;

foreach port( ports ) {

  number_of_ports ++;
  to = get_kb_item( "/tmp/ConnectTimeout/TCP/" + port );
  if( to ) {
    timeouts++;
  } else {
    s = open_sock_tcp( port, transport:ENCAPS_IP );
    if( ! s ) {
      report[port] = 'This port was detected as being open by a port scanner but is now closed.\n' +
                     'This service might have been crashed by a port scanner or by a plugin\n';
    } else {
      close( s );
      at_least_one ++;
    }
  }
}


if( number_of_ports == 0 ) exit( 0 );

if( at_least_one > 0 || number_of_ports == 1 ) {
 foreach port (keys(report))
 {
  log_message(port:port, data:report[port]);
 }
}
else
{
 text = "
The scanner cannot reach any of the previously open ports of the remote
host at the end of its scan.
";
 if (timeouts > 0)
 {
   text = "
** ";
   if (timeouts == number_of_ports)
    text += "All ports";
   else
    text = strcat(text, "Some of the ports (", timeouts, "/", number_of_ports, ")");
   text += " were skipped by this check because some
** scripts could not connect to them before the defined timeout
";
 }
 text += "
This might be an availability problem related which might be
due to the following reasons :

- The remote host is now down, either because a user turned it
off during the scan";

 if(safe_checks() == 0) text +=
" or a selected denial of service was effective against
this host";

text += '

- A network outage has been experienced during the scan, and the remote
network cannot be reached from the scanner server any more

- The scanner has been blacklisted by the system administrator
or by automatic intrusion detection/prevention systems which have detected the
vulnerability assessment.

In any case, the audit of the remote host might be incomplete and may need to
be done again
';

 log_message(port:0, data:text);
}