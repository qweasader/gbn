# SPDX-FileCopyrightText: 2008 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80095");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("XOT Detection");
  script_copyright("Copyright (C) 2008 Michel Arboi");
  script_dependencies("find_service1.nasl", "find_service2.nasl");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_require_ports(1998);

  script_tag(name:"summary", value:"This plugin detects XOT (X.25 over TCP).

  The remote target is an XOT router.
  For more information, read RFC 1613 or the referenced URL.");

  script_xref(name:"URL", value:"http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/x25.pdf");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
# include('dump.inc');
include("port_service_func.inc");
include("string_hex_func.inc");

port = 1998;
if (! get_port_state(port)) exit(0);

# XOT is not silent: it abruptly closes the connection when it receives
# invalid data
#if (silent_service(port)) exit(0);

# By the way, GET and HELP are definitely invalid. So...
b = unknown_banner_get(port: port, dontfetch: TRUE);
if (strlen(b) > 0) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
x25 = '\x20'      # Data for user, local ack, mod-128 seq
                  # LGCN = 0
    + '\0'        # LCN = 0 (reserved => invalid)
    + '\0'        # Data packet
    + '\0\0\0\0'; # Data

# XOT encapsulation (RFC 1613):
# 2 bytes for version (must be 0) + 2 bytes for length of X25 packet
len = strlen(x25);
xot = raw_string(0, 0, (len >> 8), (len & 0xFF));

send(socket: soc, data: xot + x25);
# t1 = unixtime();
r = recv(socket: soc, length: 512);
# t2 = unixtime();
close(soc);
# dump(dtitle: 'XOT', ddata: r);
lenxot = strlen(r);
if (lenxot < 4) exit(0);
if (r[0] != '\0' || r[1] != '\0') exit(0);
lenx25 = (ord(r[2]) << 8) | ord(r[3]);
if (lenx25 + 4 != lenxot) exit(0);
service_register(port: port, proto: 'xot');
log_message(port);
