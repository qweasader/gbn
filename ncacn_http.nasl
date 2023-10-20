# SPDX-FileCopyrightText: 2005 Alert4Web.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10761");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detect CIS ports");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Alert4Web.com");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ncacn_http");

  script_xref(name:"URL", value:"http://support.microsoft.com/support/kb/articles/Q282/2/61.ASP");
  script_xref(name:"URL", value:"http://msdn.microsoft.com/library/en-us/dndcom/html/cis.asp");

  script_tag(name:"solution", value:"Disable CIS with DCOMCNFG or protect CIS ports by a Firewall.");

  script_tag(name:"summary", value:"This detects the CIS ports by connecting to the server and
  processing the buffer received.

  CIS (COM+ Internet Services) are RPC over HTTP tunneling and requires IIS to operate.
  CIS ports shouldn't be visible on internet but only behind a firewall.

  If you do not use this service, then disable it as it may become
  a security threat in the future, if a vulnerability is discovered.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(proto:"ncacn_http", nodefault:TRUE);

if(!port)
  exit(0);

banner = get_kb_item("ncacn_http/banner/" + port);
if(banner) {
  data = string("There is a CIS (COM+ Internet Services) on this port\nServer banner :\n", banner);
  log_message(port:port, data:data);
}

exit(0);
