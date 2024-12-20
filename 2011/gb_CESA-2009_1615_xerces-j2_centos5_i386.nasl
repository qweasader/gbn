# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-December/016368.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880711");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2009:1615");
  script_cve_id("CVE-2009-2625");
  script_name("CentOS Update for xerces-j2 CESA-2009:1615 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-j2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"xerces-j2 on CentOS 5");
  script_tag(name:"insight", value:"The xerces-j2 packages provide the Apache Xerces2 Java Parser, a
  high-performance XML parser. A Document Type Definition (DTD) defines the
  legal syntax (and also which elements can be used) for certain types of
  files, such as XML files.

  A flaw was found in the way the Apache Xerces2 Java Parser processed the
  SYSTEM identifier in DTDs. A remote attacker could provide a
  specially-crafted XML file, which once parsed by an application using the
  Apache Xerces2 Java Parser, would lead to a denial of service (application
  hang due to excessive CPU use). (CVE-2009-2625)

  Users should upgrade to these updated packages, which contain a backported
  patch to correct this issue. Applications using the Apache Xerces2 Java
  Parser must be restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.7.1~7jpp.2.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xerces-j2-demo", rpm:"xerces-j2-demo~2.7.1~7jpp.2.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xerces-j2-javadoc-apis", rpm:"xerces-j2-javadoc-apis~2.7.1~7jpp.2.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xerces-j2-javadoc-impl", rpm:"xerces-j2-javadoc-impl~2.7.1~7jpp.2.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xerces-j2-javadoc-other", rpm:"xerces-j2-javadoc-other~2.7.1~7jpp.2.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xerces-j2-javadoc-xni", rpm:"xerces-j2-javadoc-xni~2.7.1~7jpp.2.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xerces-j2-scripts", rpm:"xerces-j2-scripts~2.7.1~7jpp.2.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
