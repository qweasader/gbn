# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871569");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-03-10 06:14:29 +0100 (Thu, 10 Mar 2016)");
  script_cve_id("CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0800");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 21:31:00 +0000 (Fri, 30 Nov 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssl098e RHSA-2016:0372-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl098e'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the
  Secure Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1) protocols,
  as well as a full-strength, general purpose cryptography library.

  A padding oracle flaw was found in the Secure Sockets Layer version 2.0
  (SSLv2) protocol. An attacker can potentially use this flaw to decrypt
  RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol
  version, allowing them to decrypt such connections. This cross-protocol
  attack is publicly referred to as DROWN. (CVE-2016-0800)

  Note: This issue was addressed by disabling the SSLv2 protocol by default
  when using the 'SSLv23' connection methods, and removing support for weak
  SSLv2 cipher suites. For more information, refer to the knowledge base
  article linked to in the References section.

  It was discovered that the SSLv2 servers using OpenSSL accepted SSLv2
  connection handshakes that indicated non-zero clear key length for
  non-export cipher suites. An attacker could use this flaw to decrypt
  recorded SSLv2 sessions with the server by using it as a decryption
  oracle.(CVE-2016-0703)

  It was discovered that the SSLv2 protocol implementation in OpenSSL did
  not properly implement the Bleichenbacher protection for export cipher
  suites. An attacker could use a SSLv2 server using OpenSSL as a
  Bleichenbacher oracle. (CVE-2016-0704)

  Note: The CVE-2016-0703 and CVE-2016-0704 issues could allow for more
  efficient exploitation of the CVE-2016-0800 issue via the DROWN attack.

  A denial of service flaw was found in the way OpenSSL handled SSLv2
  handshake messages. A remote attacker could use this flaw to cause a
  TLS/SSL server using OpenSSL to exit on a failed assertion if it had both
  the SSLv2 protocol and EXPORT-grade cipher suites enabled. (CVE-2015-0293)

  A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2
  ciphers that have been disabled on the server. This could result in weak
  SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to
  man-in-the-middle attacks. (CVE-2015-3197)

  Red Hat would like to thank the OpenSSL project for reporting these issues.
  Upstream acknowledges Nimrod Aviram and Sebastian Schinzel as the original
  reporters of CVE-2016-0800 and CVE-2015-3197  David Adrian (University of
  Michigan) and J. Alex Halderman (University of Michigan) as the original
  reporters of CVE-2016-0703 and CVE-2016-0704  and Sean Burford (Google) and
  Emilia Kasper (OpenSSL development team) as the original r ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"openssl098e on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0372-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-March/msg00028.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~29.el7_2.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl098e-debuginfo", rpm:"openssl098e-debuginfo~0.9.8e~29.el7_2.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~20.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl098e-debuginfo", rpm:"openssl098e-debuginfo~0.9.8e~20.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
