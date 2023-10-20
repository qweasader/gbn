# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104038");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Nmap NSE net: http-passwd");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_xref(name:"URL", value:"http://insecure.org/news/P55-01.txt");

  script_tag(name:"summary", value:"Checks if a web server is vulnerable to directory traversal by attempting to retrieve
'/etc/passwd' or '\boot.ini'.

The script uses several technique: * Generic directory traversal by requesting paths like
'../../../../etc/passwd'. * Known specific traversals of several web servers. * Query
string traversal. This sends traversals as query string parameters to paths that look like they
refer to a local file name. The potential query is searched for in at the path controlled by the
script argument 'http-passwd.root'.

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

http-passwd.root:  Query string tests will be done relative to this path.
The default value is '/'. Normally the value should contain a
leading slash. The queries will be sent with a trailing encoded null byte to
evade certain checks.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
