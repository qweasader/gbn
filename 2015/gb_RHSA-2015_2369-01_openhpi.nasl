# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871480");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-20 06:19:54 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-3248");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-10 14:55:00 +0000 (Tue, 10 Oct 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openhpi RHSA-2015:2369-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openhpi'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenHPI is an open source project created
with the intent of providing an implementation of the SA Forum's Hardware Platform
Interface (HPI). HPI provides an abstracted interface to managing computer hardware,
typically for chassis and rack based servers. HPI includes resource
modeling, access to and control over sensor, control, watchdog, and
inventory data associated with resources, abstracted System Event Log
interfaces, hardware events and alerts, and a managed hotswap interface.

It was found that the '/var/lib/openhpi' directory provided by OpenHPI used
world-writeable and world-readable permissions. A local user could use this
flaw to view, modify, and delete OpenHPI-related data, or even fill up the
storage device hosting the /var/lib directory. (CVE-2015-3248)

This issue was discovered by Marko Myllynen of Red Hat.

The openhpi packages have been upgraded to upstream version 3.4.0, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#1127908)

This update also fixes the following bug:

  * Network timeouts were handled incorrectly in the openhpid daemon. As a
consequence, network connections could fail when external plug-ins were
used. With this update, handling of network socket timeouts has been
improved in openhpid, and the described problem no longer occurs.
(BZ#1208127)

All openhpi users are advised to upgrade to these updated packages, which
correct these issues and add these enhancements.");
  script_tag(name:"affected", value:"openhpi on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2369-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00042.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"openhpi", rpm:"openhpi~3.4.0~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openhpi-debuginfo", rpm:"openhpi-debuginfo~3.4.0~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openhpi-libs", rpm:"openhpi-libs~3.4.0~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
