# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019661.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881695");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-22 10:40:39 +0530 (Fri, 22 Mar 2013)");
  script_cve_id("CVE-2012-2677");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2013:0668");
  script_name("CentOS Update for boost CESA-2013:0668 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'boost'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"boost on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The boost packages provide free, peer-reviewed, portable C++ source
  libraries with emphasis on libraries which work well with the C++ Standard
  Library.

  A flaw was found in the way the ordered_malloc() routine in Boost sanitized
  the 'next_size' and 'max_size' parameters when allocating memory. If an
  application used the Boost C++ libraries for memory allocation, and
  performed memory allocation based on user-supplied input, an attacker could
  use this flaw to crash the application or, potentially, execute arbitrary
  code with the privileges of the user running the application.
  (CVE-2012-2677)

  All users of boost are advised to upgrade to these updated packages, which
  contain a backported patch to fix this issue.");
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

  if ((res = isrpmvuln(pkg:"boost", rpm:"boost~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-date-time", rpm:"boost-date-time~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-devel", rpm:"boost-devel~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-doc", rpm:"boost-doc~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-filesystem", rpm:"boost-filesystem~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-graph", rpm:"boost-graph~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-graph-mpich2", rpm:"boost-graph-mpich2~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-graph-openmpi", rpm:"boost-graph-openmpi~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-iostreams", rpm:"boost-iostreams~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-math", rpm:"boost-math~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-mpich2", rpm:"boost-mpich2~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-mpich2-devel", rpm:"boost-mpich2-devel~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-mpich2-python", rpm:"boost-mpich2-python~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-openmpi", rpm:"boost-openmpi~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-openmpi-devel", rpm:"boost-openmpi-devel~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-openmpi-python", rpm:"boost-openmpi-python~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-program-options", rpm:"boost-program-options~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-python", rpm:"boost-python~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-regex", rpm:"boost-regex~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-serialization", rpm:"boost-serialization~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-signals", rpm:"boost-signals~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-static", rpm:"boost-static~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-system", rpm:"boost-system~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-test", rpm:"boost-test~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-thread", rpm:"boost-thread~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost-wave", rpm:"boost-wave~1.41.0~15.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
