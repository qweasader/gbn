# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882397");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-17 06:27:35 +0100 (Wed, 17 Feb 2016)");
  script_cve_id("CVE-2016-0741");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-12 02:01:00 +0000 (Wed, 12 Oct 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for 389-ds-base CESA-2016:0204 centos7");
  script_tag(name:"summary", value:"Check the version of 389-ds-base");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The 389 Directory Server is an LDAP
version 3 (LDAPv3) compliant server. The base packages include the
Lightweight Directory Access Protocol (LDAP) server and command-line
utilities for server administration.

An infinite-loop vulnerability was discovered in the 389 directory server,
where the server failed to correctly handle unexpectedly closed client
connections. A remote attacker able to connect to the server could use this
flaw to make the directory server consume an excessive amount of CPU and
stop accepting connections (denial of service). (CVE-2016-0741)

This update fixes the following bugs:

  * Previously, if a simple paged results search failed in the back end, the
simple paged results slot was not released. Consequently, the simple paged
results slots in a connection object could be accumulated. With this
update, the simple paged results slot is released correctly when a search
fails, and unused simple paged results slots are no longer left in a
connection object. (BZ#1290725)

  * Previously, when several values of the same attribute were deleted using
the ldapmodify command, and at least one of them was added again during the
same operation, the equality index was not updated. As a consequence, an
exact search for the re-added attribute value did not return the entry. The
logic of the index code has been modified to update the index if at least
one of the values in the entry changes, and the exact search for the
re-added attribute value now returns the correct entry. (BZ#1290726)

  * Prior to this update, when the cleanAllRUV task was running, a bogus
attrlist_replace error message was logged repeatedly due to a memory
corruption. With this update, the appropriate memory copy function memmove
is used, which fixes the memory corruption. As a result, the error messages
are no longer logged in this scenario. (BZ#1295684)

  * To fix a simple paged results bug, an exclusive lock on a connection was
previously added. This consequently caused a self deadlock in a particular
case. With this update, the exclusive lock on a connection has been changed
to the re-entrant type, and the self deadlock no longer occurs.
(BZ#1298105)

  * Previously, an unnecessary lock was sometimes acquired on a connection
object, which could consequently cause a deadlock. A patch has been applied
to remove the unnecessary locking, and the deadlock no longer occurs.
(BZ#1299346)

Users of 389-ds-base are advised to upgrade to these updated packages,
which correct these issues. After installing this update, the 389 server
service will be restarted automatically.");
  script_tag(name:"affected", value:"389-ds-base on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2016:0204");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-February/021677.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.4.0~26.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.4.0~26.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.4.0~26.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
