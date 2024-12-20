# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71525");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-3864", "CVE-2012-3865", "CVE-2012-3866", "CVE-2012-3867");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: puppet");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: puppet

CVE-2012-3864
Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise
before 2.5.2, allows remote authenticated users to read arbitrary
files on the puppet master server by leveraging an arbitrary user's
certificate and private key in a GET request.
CVE-2012-3865
Directory traversal vulnerability in lib/puppet/reports/store.rb in
Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise
before 2.5.2, when Delete is enabled in auth.conf, allows remote
authenticated users to delete arbitrary files on the puppet master
server via a .. (dot dot) in a node name.
CVE-2012-3866
lib/puppet/defaults.rb in Puppet 2.7.x before 2.7.18, and Puppet
Enterprise before 2.5.2, uses 0644 permissions for
last_run_report.yaml, which allows local users to obtain sensitive
configuration information by leveraging access to the puppet master
server to read this file.
CVE-2012-3867
lib/puppet/ssl/certificate_authority.rb in Puppet before 2.6.17 and
2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, does not
properly restrict the characters in the Common Name field of a
Certificate Signing Request (CSR), which makes it easier for
user-assisted remote attackers to trick administrators into signing a
crafted agent certificate via ANSI control sequences.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://projects.puppetlabs.com/projects/puppet/wiki/Release_Notes#2.7.18");
  script_xref(name:"URL", value:"http://puppetlabs.com/security/cve/cve-2012-3864/");
  script_xref(name:"URL", value:"http://puppetlabs.com/security/cve/cve-2012-3865/");
  script_xref(name:"URL", value:"http://puppetlabs.com/security/cve/cve-2012-3866/");
  script_xref(name:"URL", value:"http://puppetlabs.com/security/cve/cve-2012-3867/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3a6960ef-c8a8-11e1-9924-001fd0af1a4c.html");

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

bver = portver(pkg:"puppet");
if(!isnull(bver) && revcomp(a:bver, b:"2.7.18")<0) {
  txt += "Package puppet version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}