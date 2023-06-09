# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108455");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-08-06 13:53:41 +0200 (Mon, 06 Aug 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (NNTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("nntpserver_detect.nasl");
  script_mandatory_keys("nntp/detected");

  script_tag(name:"summary", value:"NNTP server based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("nntp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (NNTP)";
BANNER_TYPE = "NNTP Server banner";

port = nntp_get_port( default:119 );
if( ! banner = get_kb_item( "nntp/banner/" + port ) )
  exit( 0 );

# Runs on Windows, Linux and Mac OS X
# e.g 200 Kerio Connect 8.0.2 NNTP server ready
if( "Kerio Connect" >< banner || "Kerio MailServer" >< banner )
  exit( 0 );

# Without any OS Info:
# 200 NNTP server ready
if( banner == "200 NNTP server ready" ||
    banner == "201 NNTP server ready (no posting)" ) {
  exit( 0 );
}

# "Microsoft NNTP Service" according to shodan
# 200 NNTP Service 6.0.3790.3959 Version: 6.0.3790.3959 Posting Allowed
if( banner =~ "^200 NNTP Service [0-9.]+ Version: [0-9.]+ Posting Allowed$" ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# Runs on Windows only
if( banner == "200 CCProxy NNTP Service" ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# Runs on Windows only
# 200 NNTP-Server Classic Hamster Version 2.1 (Build 2.1.0.11) (post ok) says: Hi!
# 200 NNTP-Server Classic Hamster Vr. 2.1 (Build 2.1.0.11) (post ok) says: Hi!
if( "NNTP-Server Classic Hamster" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# "Leafnode is an Open-Source package and runs on Linux, FreeBSD, Solaris, and probably most Unix flavours."
# 200 Leafnode NNTP Daemon, version 1.11.6 running at example.com (my fqdn: example.org)
# 200 Leafnode NNTP daemon, version 2.0.0.alpha20140727b at example.com
if( " Leafnode NNTP " >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# "Citadel is intended to run on any Unix-like operating system. The primary development platform is Linux, running on 32-bit Intel. It is also known to work on Solaris (version 8 or newer), FreeBSD (version 6.0 or newer), OpenBSD (version 4.0 or newer), and Mac OS X (version 10.1 or newer). "
# 200 example.com NNTP Citadel server is not finished yet
if( " NNTP Citadel server " >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# "Mailtraq is a commercial mail and groupware server. It runs on Microsoft Windows."
# 200 example.com ready for action (Mailtraq 2.17.7.3560/NNTP)
# 200 example.com ready for action (Mailtraq 1.1.5.1167/NNTP)
if( "(Mailtraq " >< banner && "NNTP)" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# 200 Lotus Domino NNTP Server for Windows/32 (Release 5.0.8, June 18, 2001) - OK to post
# 200 Lotus Domino NNTP Server for Windows/32 (Build 166.1, March 30, 1999) - OK to post
if( "Lotus Domino NNTP Server for Windows" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# 200 example.com InterNetNews NNRP server INN 2.6.0 ready (no posting)
if( " InterNetNews NNRP server " >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

os_register_unknown_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"nntp_banner", port:port );

exit( 0 );
