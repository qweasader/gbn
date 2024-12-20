# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70265");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0434", "CVE-2011-0435", "CVE-2011-0436", "CVE-2011-0437");
  script_name("FreeBSD Ports: dtc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: dtc

CVE-2011-0434
Multiple SQL injection vulnerabilities in Domain Technologie Control
(DTC) before 0.32.9 allow remote attackers to execute arbitrary SQL
commands via the cid parameter to (1) admin/bw_per_month.php or (2)
client/bw_per_month.php.

CVE-2011-0435
Domain Technologie Control (DTC) before 0.32.9 does not require
authentication for (1) admin/bw_per_month.php and (2)
client/bw_per_month.php, which allows remote attackers to obtain
potentially sensitive bandwidth information via a direct request.

CVE-2011-0436
The register_user function in client/new_account_form.php in Domain
Technologie Control (DTC) before 0.32.9 includes a cleartext password
in an e-mail message, which makes it easier for remote attackers to
obtain sensitive information by sniffing the network.

CVE-2011-0437
shared/inc/sql/ssh.php in the SSH accounts management implementation
in Domain Technologie Control (DTC) before 0.32.9 allows remote
authenticated users to delete arbitrary accounts via the edssh_account
parameter in a deletesshaccount Delete action.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.debian.org/security/2011/dsa-2179");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/879b0242-c5b6-11e0-abd1-0017f22d6707.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"dtc");
if(!isnull(bver) && revcomp(a:bver, b:"0.32.9")<0) {
  txt += 'Package dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}