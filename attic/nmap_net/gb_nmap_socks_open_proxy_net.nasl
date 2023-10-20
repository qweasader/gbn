# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104135");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap NSE net: socks-open-proxy");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Checks if an open socks proxy is running on the target.

The script attempts to connect to a proxy server and send socks4 and socks5 payloads. It is
considered an open proxy if the script receives a Request Granted response from the target port.

The payloads try to open a connection to www.google.com port 80.  A different test host can be
passed as 'proxy.url' argument.

SYNTAX:

proxy.url:  URL that will be requested to the proxy.


proxy.pattern:  Pattern that will be searched inside the request results.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
