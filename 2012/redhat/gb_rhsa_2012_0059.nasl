# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-January/msg00021.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870668");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-07-09 10:44:57 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-4108", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2012:0059-01");
  script_name("RedHat Update for openssl RHSA-2012:0059-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"openssl on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a
  full-strength, general purpose cryptography library.

  It was discovered that the Datagram Transport Layer Security (DTLS)
  protocol implementation in OpenSSL leaked timing information when
  performing certain operations. A remote attacker could possibly use this
  flaw to retrieve plain text from the encrypted packets by using a DTLS
  server as a padding oracle. (CVE-2011-4108)

  An information leak flaw was found in the SSL 3.0 protocol implementation
  in OpenSSL. Incorrect initialization of SSL record padding bytes could
  cause an SSL client or server to send a limited amount of possibly
  sensitive data to its SSL peer via the encrypted connection.
  (CVE-2011-4576)

  A denial of service flaw was found in the RFC 3779 implementation in
  OpenSSL. A remote attacker could use this flaw to make an application using
  OpenSSL exit unexpectedly by providing a specially-crafted X.509
  certificate that has malformed RFC 3779 extension data. (CVE-2011-4577)

  It was discovered that OpenSSL did not limit the number of TLS/SSL
  handshake restarts required to support Server Gated Cryptography. A remote
  attacker could use this flaw to make a TLS/SSL server using OpenSSL consume
  an excessive amount of CPU by continuously restarting the handshake.
  (CVE-2011-4619)

  All OpenSSL users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. For the update to take effect,
  all services linked to the OpenSSL library must be restarted, or the system
  rebooted.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.0~20.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.0~20.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.0~20.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
