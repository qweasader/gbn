# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882039");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-10-01 16:59:36 +0530 (Wed, 01 Oct 2014)");
  script_cve_id("CVE-2013-1418", "CVE-2013-6800", "CVE-2014-4341", "CVE-2014-4344");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for krb5-devel CESA-2014:1245 centos5");
  script_tag(name:"insight", value:"Kerberos is an authentication system which allows clients and services to
authenticate to each other with the help of a trusted third party, a
Kerberos Key Distribution Center (KDC).

It was found that if a KDC served multiple realms, certain requests could
cause the setup_server_realm() function to dereference a NULL pointer.
A remote, unauthenticated attacker could use this flaw to crash the KDC
using a specially crafted request. (CVE-2013-1418, CVE-2013-6800)

A NULL pointer dereference flaw was found in the MIT Kerberos SPNEGO
acceptor for continuation tokens. A remote, unauthenticated attacker could
use this flaw to crash a GSSAPI-enabled server application. (CVE-2014-4344)

A buffer over-read flaw was found in the way MIT Kerberos handled certain
requests. A man-in-the-middle attacker with a valid Kerberos ticket who is
able to inject packets into a client or server application's GSSAPI session
could use this flaw to crash the application. (CVE-2014-4341)

This update also fixes the following bugs:

  * Prior to this update, the libkrb5 library occasionally attempted to free
already freed memory when encrypting credentials. As a consequence, the
calling process terminated unexpectedly with a segmentation fault.
With this update, libkrb5 frees memory correctly, which allows the
credentials to be encrypted appropriately and thus prevents the mentioned
crash. (BZ#1004632)

  * Previously, when the krb5 client library was waiting for a response from
a server, the timeout variable in certain cases became a negative number.
Consequently, the client could enter a loop while checking for responses.
With this update, the client logic has been modified and the described
error no longer occurs. (BZ#1089732)

All krb5 users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
updated packages, the krb5kdc daemon will be restarted automatically.");
  script_tag(name:"affected", value:"krb5-devel on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CESA", value:"2014:1245");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-September/020626.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5-devel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~78.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~78.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~78.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.6.1~78.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~78.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.1~78.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
