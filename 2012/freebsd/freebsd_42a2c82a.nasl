# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71290");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
  script_name("FreeBSD Ports: quagga");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  quagga
   quagga-re

CVE-2012-0249
Buffer overflow in the ospf_ls_upd_list_lsa function in ospf_packet.c
in the OSPFv2 implementation in ospfd in Quagga before 0.99.20.1
allows remote attackers to cause a denial of service (assertion
failure and daemon exit) via a Link State Update (aka LS Update)
packet that is smaller than the length specified in its header.
CVE-2012-0250
Buffer overflow in the OSPFv2 implementation in ospfd in Quagga before
0.99.20.1 allows remote attackers to cause a denial of service (daemon
crash) via a Link State Update (aka LS Update) packet containing a
network-LSA link-state advertisement for which the data-structure
length is smaller than the value in the Length header field.
CVE-2012-0255
The BGP implementation in bgpd in Quagga before 0.99.20.1 does not
properly use message buffers for OPEN messages, which allows remote
attackers to cause a denial of service (assertion failure and daemon
exit) via a message associated with a malformed Four-octet AS Number
Capability (aka AS4 capability).");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/551715");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/42a2c82a-75b9-11e1-89b4-001ec9578670.html");

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

bver = portver(pkg:"quagga");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.20.1")<0) {
  txt += "Package quagga version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"quagga-re");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.17.8")<0) {
  txt += "Package quagga-re version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}