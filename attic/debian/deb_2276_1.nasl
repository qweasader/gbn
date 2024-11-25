# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69982");
  script_cve_id("CVE-2011-2529", "CVE-2011-2535", "CVE-2011-2536");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2276-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2276-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2276");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-2276-1 advisory. [This VT has been merged into the VT 'deb_2276.nasl' (OID: 1.3.6.1.4.1.25623.1.0.69982).]");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Belanger reported a vulnerability in Asterisk identified as AST-2011-008 (CVE-2011-2529) through which an unauthenticated attacker may crash an Asterisk server remotely. A package containing a NULL char causes the SIP header parser to alter unrelated memory structures.

Jared Mauch reported a vulnerability in Asterisk identified as AST-2011-009 through which an unauthenticated attacker may crash an Asterisk server remotely. If a user sends a package with a Contact header with a missing left angle bracket (<) the server will crash. A possible workaround is to disable chan_sip.

The vulnerability identified as AST-2011-010 (CVE-2011-2535) reported about an input validation error in the IAX2 channel driver. An unauthenticated attacker may crash an Asterisk server remotely by sending a crafted option control frame.

For the oldstable distribution (lenny), this problem has been fixed in version 1.4.21.2~dfsg-3+lenny5.

For the stable distribution (squeeze), this problem has been fixed in version 1.6.2.9-2+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in version 1:1.8.4.3-1.

For the unstable distribution (sid), this problem has been fixed in version 1:1.8.4.3-1.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);