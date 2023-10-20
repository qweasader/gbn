# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104127");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Nmap NSE net: informix-brute");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Performs brute force password auditing against IBM Informix Dynamic Server.

SYNTAX:

brute.firstonly:  stop guessing after first password is found
(default: false)

brute.unique:  make sure that each password is only guessed once
(default: true)

brute.retries:  the number of times to retry if recoverable failures
occurs. (default: 3)

brute.mode:  can be user, pass or creds and determines what mode to run
the engine in.

  - user - the unpwdb library is used to guess passwords, every password
password is tried for each user. (The user iterator is in the
outer loop)

  - pass - the unpwdb library is used to guess passwords, each password
is tried for every user. (The password iterator is in the
outer loop)

  - creds- a set of credentials (username and password pairs) are
guessed against the service. This allows for lists of known
or common username and password combinations to be tested.
If no mode is specified and the script has not added any custom
iterator the pass mode will be enabled.

informix.instance:  specifies the Informix instance to connect to

brute.useraspass:  guess the username as password for each user
(default: true)

brute.passonly:  iterate over passwords only for services that provide
only a password for authentication. (default: false)

brute.credfile:  a file containing username and password pairs delimited
by '/'

brute.threads:  the number of initial worker threads, the number of
active threads will be automatically adjusted.

brute.delay:  the number of seconds to wait between guesses (default: 0)");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
