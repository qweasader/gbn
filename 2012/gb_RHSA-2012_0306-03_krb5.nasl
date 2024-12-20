# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00050.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870562");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-21 18:57:08 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-1526");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:0306-03");
  script_name("RedHat Update for krb5 RHSA-2012:0306-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"krb5 on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other using symmetric encryption and a
  trusted third-party, the Key Distribution Center (KDC).

  It was found that ftpd, a Kerberos-aware FTP server, did not properly drop
  privileges. On Red Hat Enterprise Linux 5, the ftpd daemon did not check
  for the potential failure of the effective group ID change system call. If
  the group ID change failed, a remote FTP user could use this flaw to gain
  unauthorized read or write access to files that are owned by the root
  group. (CVE-2011-1526)

  Red Hat would like to thank the MIT Kerberos project for reporting this
  issue. Upstream acknowledges Tim Zingelman as the original reporter.

  This update also fixes the following bugs:

  * Due to a mistake in the Kerberos libraries, a client could fail to
  contact a Key Distribution Center (KDC) or terminate unexpectedly if the
  client had already more than 1024 file descriptors in use. This update
  backports modifications to the Kerberos libraries and the libraries use
  the poll() function instead of the select() function, as poll() does not
  have this limitation. (BZ#701444)

  * The KDC failed to release memory when processing a TGS (ticket-granting
  server) request from a client if the client request included an
  authenticator with a subkey. As a result, the KDC consumed an excessive
  amount of memory. With this update, the code releasing the memory has been
  added and the problem no longer occurs. (BZ#708516)

  * Under certain circumstances, if services requiring Kerberos
  authentication sent two authentication requests to the authenticating
  server, the second authentication request was flagged as a replay attack.
  As a result, the second authentication attempt was denied. This update
  applies an upstream patch that fixes this bug. (BZ#713500)

  * Previously, if Kerberos credentials had expired, the klist command could
  terminate unexpectedly with a segmentation fault when invoked with the -s
  option. This happened when klist encountered and failed to process an entry
  with no realm name while scanning the credential cache. With this update,
  the underlying code has been modified and the command handles such entries
  correctly. (BZ#729067)

  * Due to a regression, multi-line FTP macros terminated prematurely with a
  segmentation fault. This occurred because the previously-added patch failed
  to properly support multi-line macros. This update restores the support for
  multi-line macros and the problem no longer occurs. (BZ#735363, BZ#736132)

  All users of krb5 are advised to upgrade to these updated packages, which
  resolve these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.6.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
