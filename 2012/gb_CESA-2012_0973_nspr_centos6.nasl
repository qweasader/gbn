# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018724.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881105");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:09:14 +0530 (Mon, 30 Jul 2012)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2012:0973");
  script_name("CentOS Update for nspr CESA-2012:0973 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"nspr on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support
  the cross-platform development of security-enabled client and server
  applications. Netscape Portable Runtime (NSPR) provides platform
  independence for non-GUI operating system facilities.

  It was found that a Certificate Authority (CA) issued a subordinate CA
  certificate to its customer, that could be used to issue certificates for
  any name. This update renders the subordinate CA certificate as untrusted.
  (BZ#798533)

  Note: This fix only applies to applications using the NSS Builtin Object
  Token. It does not render the certificates untrusted for applications that
  use the NSS library, but do not use the NSS Builtin Object Token.

  The nspr package has been upgraded to upstream version 4.9, which provides
  a number of bug fixes and enhancements over the previous version.
  (BZ#799193)

  The nss-util package has been upgraded to upstream version 3.13.3, which
  provides a number of bug fixes and enhancements over the previous version.
  (BZ#799192)

  The nss package has been upgraded to upstream version 3.13.3, which
  provides numerous bug fixes and enhancements over the previous version. In
  particular, SSL 2.0 is now disabled by default, support for SHA-224 has
  been added, PORT_ErrorToString and PORT_ErrorToName now return the error
  message and symbolic name of an NSS error code, and NSS_GetVersion now
  returns the NSS version string. (BZ#744070)

  These updated nss, nss-util, and nspr packages also provide fixes for the
  following bugs:

  * A PEM module internal function did not clean up memory when detecting a
  non-existent file name. Consequently, memory leaks in client code occurred.
  The code has been improved to deallocate such temporary objects and as a
  result the reported memory leakage is gone. (BZ#746632)

  * Recent changes to NSS re-introduced a problem where applications could
  not use multiple SSL client certificates in the same process. Therefore,
  any attempt to run commands that worked with multiple SSL client
  certificates, such as the 'yum repolist' command, resulted in a
  re-negotiation handshake failure. With this update, a revised patch
  correcting this problem has been applied to NSS, and using multiple SSL
  client certificates in the same process is now possible again. (BZ#761086)

  * The PEM module did not fully initialize newly constructed objects with
  function pointers set to NULL. Consequently, a segmentation violation in
  libcurl was sometimes experienced while accessing a package repository.
  With this update, the code h ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.13.3~6.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.13.3~6.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.13.3~6.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.13.3~6.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.13.3~6.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.13.3~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.13.3~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
