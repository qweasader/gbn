# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882016");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-10 06:20:36 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-0240");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for mod_wsgi CESA-2014:1091 centos7");
  script_tag(name:"insight", value:"The mod_wsgi adapter is an Apache module
that provides a WSGI-compliant interface for hosting Python-based web
applications within Apache.

It was found that mod_wsgi did not properly drop privileges if the call to
setuid() failed. If mod_wsgi was set up to allow unprivileged users to run
WSGI applications, a local user able to run a WSGI application could
possibly use this flaw to escalate their privileges on the system.
(CVE-2014-0240)

Note: mod_wsgi is not intended to provide privilege separation for WSGI
applications. Systems relying on mod_wsgi to limit or sandbox the
privileges of mod_wsgi applications should migrate to a different solution
with proper privilege separation.

Red Hat would like to thank Graham Dumpleton for reporting this issue.
Upstream acknowledges Rbert Kisteleki as the original reporter.

All mod_wsgi users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.");
  script_tag(name:"affected", value:"mod_wsgi on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CESA", value:"2014:1091");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-August/020506.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_wsgi'
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

  if ((res = isrpmvuln(pkg:"mod_wsgi", rpm:"mod_wsgi~3.4~12.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
