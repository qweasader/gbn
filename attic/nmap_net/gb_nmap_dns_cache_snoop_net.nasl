# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104033");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nmap NSE net: dns-cache-snoop");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Performs DNS cache snooping against a DNS server.

There are two modes of operation, controlled by the 'dns-cache-snoop.mode' script
argument. In 'nonrecursive' mode (the default), queries are sent to the server with the
RD (recursion desired) flag set to 0. The server should respond positively to these only if it has
the domain cached. In 'timed' mode, the mean and standard deviation response times for a
cached domain are calculated by sampling the resolution of a name (www.google.com) several times.
Then, each domain is resolved and the time taken compared to the mean. If it is less than one
standard deviation over the mean, it is considered cached. The 'timed' mode inserts
entries in the cache and can only be used reliably once.

The default list of domains to check consists of the top 50 most popular sites, each site being
listed twice, once with 'www.' and once without. Use the 'dns-cache-snoop.domains' script
argument to use a different list.

SYNTAX:

dns-cache-snoop.domains:  an array of domain to check in place of
the default list.

dns-cache-snoop.mode:  which of two supported snooping methods to
use. 'nonrecursive', the default, checks if the server
returns results for non-recursive queries. Some servers may disable
this. 'timed' measures the difference in time taken to
resolve cached and non-cached hosts. This mode will pollute the DNS
cache and can only be used once reliably.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
