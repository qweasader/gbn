# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871251");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-10-01 16:58:11 +0530 (Wed, 01 Oct 2014)");
  script_cve_id("CVE-2014-1568");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for nss RHSA-2014:1307-01");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support
the cross-platform development of security-enabled client and server
applications. Netscape Portable Runtime (NSPR) provides platform
independence for non-GUI operating system facilities.

A flaw was found in the way NSS parsed ASN.1 (Abstract Syntax Notation One)
input from certain RSA signatures. A remote attacker could use this flaw to
forge RSA certificates by providing a specially crafted signature to an
application using NSS. (CVE-2014-1568)

Red Hat would like to thank the Mozilla project for reporting this issue.
Upstream acknowledges Antoine Delignat-Lavaud and Intel Product Security
Incident Response Team as the original reporters.

All NSS users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing this
update, applications using NSS must be restarted for this update to
take effect.");
  script_tag(name:"affected", value:"nss on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"RHSA", value:"2014:1307-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-September/msg00054.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6|5)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.16.2~7.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.16.2~7.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.16.2~7.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn", rpm:"nss-softokn~3.16.2~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-debuginfo", rpm:"nss-softokn-debuginfo~3.16.2~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-devel", rpm:"nss-softokn-devel~3.16.2~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-freebl", rpm:"nss-softokn-freebl~3.16.2~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-freebl-devel", rpm:"nss-softokn-freebl-devel~3.16.2~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.16.2~7.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.16.2~7.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.16.2~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-debuginfo", rpm:"nss-util-debuginfo~3.16.2~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.16.2~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.16.1~7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.16.1~7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.16.1~7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn", rpm:"nss-softokn~3.14.3~12.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-debuginfo", rpm:"nss-softokn-debuginfo~3.14.3~12.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-devel", rpm:"nss-softokn-devel~3.14.3~12.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-freebl", rpm:"nss-softokn-freebl~3.14.3~12.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-freebl-devel", rpm:"nss-softokn-freebl-devel~3.14.3~12.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.16.1~7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.16.1~7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.16.1~2.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-debuginfo", rpm:"nss-util-debuginfo~3.16.1~2.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.16.1~2.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.16.1~4.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.16.1~4.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.16.1~4.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.16.1~4.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.16.1~4.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
