# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871291");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-11-13 06:29:06 +0100 (Thu, 13 Nov 2014)");
  script_cve_id("CVE-2014-8564");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for gnutls RHSA-2014:1846-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The GnuTLS library provides support for cryptographic algorithms and for
protocols such as Transport Layer Security (TLS). The gnutls packages also
include the libtasn1 library, which provides Abstract Syntax Notation One
(ASN.1) parsing and structures management, and Distinguished Encoding Rules
(DER) encoding and decoding functions.

An out-of-bounds memory write flaw was found in the way GnuTLS parsed
certain ECC (Elliptic Curve Cryptography) certificates or certificate
signing requests (CSR). A malicious user could create a specially crafted
ECC certificate or a certificate signing request that, when processed by an
application compiled against GnuTLS (for example, certtool), could cause
that application to crash or execute arbitrary code with the permissions of
the user running the application. (CVE-2014-8564)

Red Hat would like to thank GnuTLS upstream for reporting this issue.
Upstream acknowledges Sean Burford as the original reporter.

All gnutls users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. For the update to take
effect, all applications linked to the GnuTLS or libtasn1 library must
be restarted.");
  script_tag(name:"affected", value:"gnutls on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:1846-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-November/msg00027.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.1.18~10.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-c++", rpm:"gnutls-c++~3.1.18~10.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-dane", rpm:"gnutls-dane~3.1.18~10.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~3.1.18~10.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~3.1.18~10.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~3.1.18~10.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
