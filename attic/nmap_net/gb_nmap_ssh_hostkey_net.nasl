# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104056");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nmap NSE net: ssh-hostkey");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Shows SSH hostkeys.

Shows the target SSH server's key fingerprint and (with high enough verbosity level) the public key
itself.  It records the discovered host keys in 'nmap.registry' for use by other scripts.
Output can be controlled with the 'ssh_hostkey' script argument.

SYNTAX:

ssh_hostkey:  Controls the output format of keys. Multiple values may be
given, separated by spaces. Possible values are

  - ''full'': The entire key, not just the fingerprint.

  - ''bubble'': Bubble Babble output,

  - ''visual'': Visual ASCII art representation.

  - ''all'': All of the above.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
