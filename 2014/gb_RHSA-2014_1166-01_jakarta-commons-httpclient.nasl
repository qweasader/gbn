# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871238");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-09 05:54:36 +0200 (Tue, 09 Sep 2014)");
  script_cve_id("CVE-2014-3577", "CVE-2012-6153");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("RedHat Update for jakarta-commons-httpclient RHSA-2014:1166-01");
  script_tag(name:"insight", value:"Jakarta Commons HTTPClient implements the client side of HTTP standards.

It was discovered that the HTTPClient incorrectly extracted host name from
an X.509 certificate subject's Common Name (CN) field. A man-in-the-middle
attacker could use this flaw to spoof an SSL server using a specially
crafted X.509 certificate. (CVE-2014-3577)

For additional information on this flaw, refer to the Knowledgebase
article in the References section.

All jakarta-commons-httpclient users are advised to upgrade to these
updated packages, which contain a backported patch to correct this issue.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

This update is available via the Red Hat Network. Details on how to use the
Red Hat Network to apply this update are available at


1129074 - CVE-2014-3577 Apache HttpComponents client: SSL hostname verification bypass, incomplete CVE-2012-6153 fix

6. Package List:

Red Hat Enterprise Linux Desktop (v. 5 client):

Source:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.src.rpm

i386:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.i386.rpm

x86_64:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.x86_64.rpm
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.x86_64.rpm

Red Hat Enterprise Linux Desktop Workstation (v. 5 client):

Source:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.src.rpm

i386:
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-demo-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-javadoc-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-manual-3.0-7jpp.4.el5_10.i386.rpm

x86_64:
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.x86_64.rpm
jakarta-commons-httpclient-demo-3.0-7jpp.4.el5_10.x86_64.rpm
jakarta-commons-httpclient-javadoc-3.0-7jpp.4.el5_10.x86_64.rpm
jakarta-commons-httpclient-manual-3.0-7jpp.4.el5_10.x86_64.rpm

Red Hat Enterprise Linux (v. 5 server):

Source:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.src.rpm

i386:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_ ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"jakarta-commons-httpclient on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"RHSA", value:"2014:1166-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-September/msg00017.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'jakarta-commons-httpclient'
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

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient", rpm:"jakarta-commons-httpclient~3.1~16.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient", rpm:"jakarta-commons-httpclient~3.1~0.9.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient-debuginfo", rpm:"jakarta-commons-httpclient-debuginfo~3.1~0.9.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient", rpm:"jakarta-commons-httpclient~3.0~7jpp.4.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient-debuginfo", rpm:"jakarta-commons-httpclient-debuginfo~3.0~7jpp.4.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient-demo", rpm:"jakarta-commons-httpclient-demo~3.0~7jpp.4.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient-javadoc", rpm:"jakarta-commons-httpclient-javadoc~3.0~7jpp.4.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient-manual", rpm:"jakarta-commons-httpclient-manual~3.0~7jpp.4.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
