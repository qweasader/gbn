# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882014");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-10 06:20:30 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-3490", "CVE-2012-0818");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for resteasy-base CESA-2014:1011 centos7");
  script_tag(name:"insight", value:"RESTEasy contains a JBoss project that
provides frameworks to help build RESTful Web Services and RESTful Java
applications. It is a fully certified and portable implementation of the
JAX-RS specification.

It was found that the fix for CVE-2012-0818 was incomplete: external
parameter entities were not disabled when the
resteasy.document.expand.entity.references parameter was set to false.
A remote attacker able to send XML requests to a RESTEasy endpoint could
use this flaw to read files accessible to the user running the application
server, and potentially perform other more advanced XXE attacks.
(CVE-2014-3490)

This issue was discovered by David Jorm of Red Hat Product Security.

All resteasy-base users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue.");
  script_tag(name:"affected", value:"resteasy-base on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CESA", value:"2014:1011");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-August/020469.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'resteasy-base'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"resteasy-base", rpm:"resteasy-base~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-atom-provider", rpm:"resteasy-base-atom-provider~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jackson-provider", rpm:"resteasy-base-jackson-provider~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-javadoc", rpm:"resteasy-base-javadoc~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxb-provider", rpm:"resteasy-base-jaxb-provider~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxrs", rpm:"resteasy-base-jaxrs~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxrs-all", rpm:"resteasy-base-jaxrs-all~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxrs-api", rpm:"resteasy-base-jaxrs-api~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jettison-provider", rpm:"resteasy-base-jettison-provider~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-providers-pom", rpm:"resteasy-base-providers-pom~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-tjws", rpm:"resteasy-base-tjws~2.3.5~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
