# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882473");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-26 05:18:56 +0200 (Tue, 26 Apr 2016)");
  script_cve_id("CVE-2016-1978", "CVE-2016-1979");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for nss CESA-2016:0684 centos5");
  script_tag(name:"summary", value:"Check the version of nss");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set
of libraries designed to support the cross-platform development of
security-enabled client and server applications. Netscape Portable Runtime (NSPR)
provides platform independence for non-GUI operating system facilities.

The following packages have been upgraded to a newer upstream version: nss
3.21.0, nspr 4.11.0. (BZ#1297944, BZ#1297943)

Security Fix(es):

  * A use-after-free flaw was found in the way NSS handled DHE
(Diffie-Hellman key exchange) and ECDHE (Elliptic Curve Diffie-Hellman key
exchange) handshake messages. A remote attacker could send a specially
crafted handshake message that, when parsed by an application linked
against NSS, would cause that application to crash or, under certain
special conditions, execute arbitrary code using the permissions of the
user running the application. (CVE-2016-1978)

  * A use-after-free flaw was found in the way NSS processed certain DER
(Distinguished Encoding Rules) encoded cryptographic keys. An attacker
could use this flaw to create a specially crafted DER encoded certificate
which, when parsed by an application compiled against the NSS library,
could cause that application to crash, or execute arbitrary code using the
permissions of the user running the application. (CVE-2016-1979)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Eric Rescorla as the original reporter of
CVE-2016-1978 and Tim Taubert as the original reporter of CVE-2016-1979.");
  script_tag(name:"affected", value:"nss on CentOS 5");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0684");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-April/021847.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.21.0~6.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.21.0~6.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.21.0~6.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.21.0~6.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
