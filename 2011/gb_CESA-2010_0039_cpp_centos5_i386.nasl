# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-January/016445.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880596");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2010:0039");
  script_cve_id("CVE-2009-3736");
  script_name("CentOS Update for cpp CESA-2010:0039 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cpp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"cpp on CentOS 5");
  script_tag(name:"insight", value:"The gcc and gcc4 packages include, among others, C, C++, and Java GNU
  compilers and related support libraries. libgcj contains a copy of GNU
  Libtool's libltdl library.

  A flaw was found in the way GNU Libtool's libltdl library looked for
  libraries to load. It was possible for libltdl to load a malicious library
  from the current working directory. In certain configurations, if a local
  attacker is able to trick a local user into running a Java application
  (which uses a function to load native libraries, such as
  System.loadLibrary) from within an attacker-controlled directory containing
  a malicious library or module, the attacker could possibly execute
  arbitrary code with the privileges of the user running the Java
  application. (CVE-2009-3736)

  All gcc and gcc4 users should upgrade to these updated packages, which
  contain a backported patch to correct this issue. All running Java
  applications using libgcj must be restarted for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"cpp", rpm:"cpp~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc", rpm:"gcc~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-c++", rpm:"gcc-c++~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-gfortran", rpm:"gcc-gfortran~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-gnat", rpm:"gcc-gnat~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-java", rpm:"gcc-java~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-objc", rpm:"gcc-objc~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-objc++", rpm:"gcc-objc++~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcc", rpm:"libgcc~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj", rpm:"libgcj~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj-devel", rpm:"libgcj-devel~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj-src", rpm:"libgcj-src~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgfortran", rpm:"libgfortran~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnat", rpm:"libgnat~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmudflap", rpm:"libmudflap~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmudflap-devel", rpm:"libmudflap-devel~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libobjc", rpm:"libobjc~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++", rpm:"libstdc++~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++-devel", rpm:"libstdc++-devel~4.1.2~46.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
