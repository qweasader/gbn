# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017375.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880525");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:0346");
  script_cve_id("CVE-2011-1024");
  script_name("CentOS Update for compat-openldap CESA-2011:0346 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openldap'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"compat-openldap on CentOS 5");
  script_tag(name:"insight", value:"OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  A flaw was found in the way OpenLDAP handled authentication failures being
  passed from an OpenLDAP slave to the master. If OpenLDAP was configured
  with a chain overlay and it forwarded authentication failures, OpenLDAP
  would bind to the directory as an anonymous user and return success, rather
  than return failure on the authenticated bind. This could allow a user on a
  system that uses LDAP for authentication to log into a directory-based
  account without knowing the password. (CVE-2011-1024)

  This update also fixes the following bug:

  * Previously, multiple concurrent connections to an OpenLDAP server could
  cause the slapd service to terminate unexpectedly with an assertion error.
  This update adds mutexes to protect multiple threads from accessing a
  structure with a connection, and the slapd service no longer crashes.
  (BZ#677611)

  Users of OpenLDAP should upgrade to these updated packages, which contain
  backported patches to resolve these issues. After installing this update,
  the OpenLDAP daemons will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"compat-openldap", rpm:"compat-openldap~2.3.43_2.2.29~12.el5_6.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.3.43~12.el5_6.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.3.43~12.el5_6.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.3.43~12.el5_6.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.3.43~12.el5_6.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-overlays", rpm:"openldap-servers-overlays~2.3.43~12.el5_6.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.3.43~12.el5_6.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
