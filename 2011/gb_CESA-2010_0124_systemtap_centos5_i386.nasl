# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-March/016540.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880651");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2010:0124");
  script_cve_id("CVE-2009-4273", "CVE-2010-0411");
  script_name("CentOS Update for systemtap CESA-2010:0124 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemtap'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"systemtap on CentOS 5");
  script_tag(name:"insight", value:"SystemTap is an instrumentation system for systems running the Linux
  kernel, version 2.6. Developers can write scripts to collect data on the
  operation of the system.

  A flaw was found in the SystemTap compile server, stap-server, an optional
  component of SystemTap. This server did not adequately sanitize input
  provided by the stap-client program, which may allow a remote user to
  execute arbitrary shell code with the privileges of the compile server
  process, which could possibly be running as the root user. (CVE-2009-4273)

  Note: stap-server is not run by default. It must be started by a user or
  administrator.

  A buffer overflow flaw was found in SystemTap's tapset __get_argv()
  function. If a privileged user ran a SystemTap script that called this
  function, a local, unprivileged user could, while that script is still
  running, trigger this flaw and cause memory corruption by running a command
  with a large argument list, which may lead to a system crash or,
  potentially, arbitrary code execution with root privileges. (CVE-2010-0411)

  Note: SystemTap scripts that call __get_argv(), being a privileged
  function, can only be executed by the root user or users in the stapdev
  group. As well, if such a script was compiled and installed by root, users
  in the stapusr group would also be able to execute it.

  SystemTap users should upgrade to these updated packages, which contain
  backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"systemtap", rpm:"systemtap~0.9.7~5.el5_4.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-client", rpm:"systemtap-client~0.9.7~5.el5_4.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-initscript", rpm:"systemtap-initscript~0.9.7~5.el5_4.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-runtime", rpm:"systemtap-runtime~0.9.7~5.el5_4.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-sdt-devel", rpm:"systemtap-sdt-devel~0.9.7~5.el5_4.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-server", rpm:"systemtap-server~0.9.7~5.el5_4.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-testsuite", rpm:"systemtap-testsuite~0.9.7~5.el5_4.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
