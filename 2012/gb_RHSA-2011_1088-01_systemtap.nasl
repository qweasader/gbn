# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-July/msg00029.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870636");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-06 10:38:24 +0530 (Wed, 06 Jun 2012)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-2502", "CVE-2011-2503");
  script_xref(name:"RHSA", value:"2011:1088-01");
  script_name("RedHat Update for systemtap RHSA-2011:1088-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemtap'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"systemtap on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"SystemTap is an instrumentation system for systems running the Linux
  kernel. The system allows developers to write scripts to collect data on
  the operation of the system.

  It was found that SystemTap did not perform proper module path sanity
  checking if a user specified a custom path to the uprobes module, used
  when performing user-space probing ('staprun -u'). A local user who is a
  member of the stapusr group could use this flaw to bypass intended
  module-loading restrictions, allowing them to escalate their privileges by
  loading an arbitrary, unsigned module. (CVE-2011-2502)

  A race condition flaw was found in the way the staprun utility performed
  module loading. A local user who is a member of the stapusr group could
  use this flaw to modify a signed module while it is being loaded,
  allowing them to escalate their privileges. (CVE-2011-2503)

  SystemTap users should upgrade to these updated packages, which contain
  backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"systemtap", rpm:"systemtap~1.4~6.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-client", rpm:"systemtap-client~1.4~6.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-debuginfo", rpm:"systemtap-debuginfo~1.4~6.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-grapher", rpm:"systemtap-grapher~1.4~6.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-initscript", rpm:"systemtap-initscript~1.4~6.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-runtime", rpm:"systemtap-runtime~1.4~6.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-sdt-devel", rpm:"systemtap-sdt-devel~1.4~6.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-server", rpm:"systemtap-server~1.4~6.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
