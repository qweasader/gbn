# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871243");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-09-17 05:57:43 +0200 (Wed, 17 Sep 2014)");
  script_cve_id("CVE-2014-0591");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for bind97 RHSA-2014:1244-01");
  script_tag(name:"insight", value:"The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
Name System (DNS) protocols. It contains a DNS server (named), a resolver
library with routines for applications to use when interfacing with DNS,
and tools for verifying that the DNS server is operating correctly.
These packages contain version 9.7 of the BIND suite.

A denial of service flaw was found in the way BIND handled queries for
NSEC3-signed zones. A remote attacker could use this flaw against an
authoritative name server that served NCES3-signed zones by sending a
specially crafted query, which, when processed, would cause named to crash.
(CVE-2014-0591)

Note: The CVE-2014-0591 issue does not directly affect the version of
bind97 shipped in Red Hat Enterprise Linux 5. This issue is being addressed
however to assure it is not introduced in future builds of bind97 (possibly
built with a different compiler or C library optimization).

This update also fixes the following bug:

  * Previously, the bind97 initscript did not check for the existence of the
ROOTDIR variable when shutting down the named daemon. As a consequence,
some parts of the file system that are mounted when using bind97 in a
chroot environment were unmounted on daemon shut down, even if bind97 was
not running in a chroot environment. With this update, the initscript has
been fixed to check for the existence of the ROOTDIR variable when
unmounting some parts of the file system on named daemon shut down. Now,
when shutting down bind97 that is not running in a chroot environment, no
parts of the file system are unmounted. (BZ#1059118)

All bind97 users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
update, the BIND daemon (named) will be restarted automatically.");
  script_tag(name:"affected", value:"bind97 on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"RHSA", value:"2014:1244-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-September/msg00031.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind97'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"bind97", rpm:"bind97~9.7.0~21.P2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind97-chroot", rpm:"bind97-chroot~9.7.0~21.P2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind97-debuginfo", rpm:"bind97-debuginfo~9.7.0~21.P2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind97-devel", rpm:"bind97-devel~9.7.0~21.P2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind97-libs", rpm:"bind97-libs~9.7.0~21.P2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind97-utils", rpm:"bind97-utils~9.7.0~21.P2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
