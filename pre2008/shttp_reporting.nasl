# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: The vulnerability reporting has been split off from the original shttp_detect.nasl. As some
# text parts and similar has been moved into this VT the Copyright and creation_date has been kept.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104261");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Deprecated Secure HyperText Transfer Protocol (S-HTTP) Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Useless services");
  script_dependencies("shttp_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("shttp/detected");

  # RFC 2660 The Secure HyperText Transfer Protocol
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc2660");

  script_tag(name:"summary", value:"This web server supports the deprecated Secure HyperText
  Transfer Protocol (S-HTTP), a cryptographic layer that was defined in 1999 by RFC 2660.");

  script_tag(name:"solution", value:"S-HTTP has never been widely implemented and the Hypertext
  Transfer Protocol Secure (HTTPS) protocol should be used instead.

  As rare or obsolete code is often badly tested, it would be safer to use another server or disable
  this layer somehow.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

if(!banner = get_kb_item("shttp/" + port + "/banner"))
  exit(0);

report = 'Received banner:\n\n' + banner;
security_message(port:port, data:report);

exit(0);
