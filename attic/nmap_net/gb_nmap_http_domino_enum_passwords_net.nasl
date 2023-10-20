# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104006");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Nmap NSE net: http-domino-enum-passwords");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Attempts to enumerate the hashed Domino Internet Passwords that are (by default) accessible by all
authenticated users. This script can also download any Domino ID Files attached to the Person
document.

SYNTAX:

domino-enum-passwords.idpath:  the path where downloaded ID files should be saved
If not given, the script will only indicate if the ID file is donwloadable or not

domino-enum-passwords.count:  the number of internet hashes and id files to fetch.
If a negative value is given, all hashes and id files are retrieved (default: 10)

domino-enum-passwords.path:  points to the path protected by authentication

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

domino-enum-passwords.hostname:  sets the host header in case of virtual hosting

http-max-cache-size:  The maximum memory size (in bytes) of the cache.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
