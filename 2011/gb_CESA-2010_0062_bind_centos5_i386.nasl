# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-January/016478.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880604");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"CESA", value:"2010:0062");
  script_cve_id("CVE-2010-0097", "CVE-2010-0290", "CVE-2009-4022");
  script_name("CentOS Update for bind CESA-2010:0062 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"bind on CentOS 5");
  script_tag(name:"insight", value:"The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
  Name System (DNS) protocols. BIND includes a DNS server (named), a resolver
  library (routines for applications to use when interfacing with DNS), and
  tools for verifying that the DNS server is operating correctly.

  A flaw was found in the BIND DNSSEC NSEC/NSEC3 validation code. If BIND was
  running as a DNSSEC-validating resolver, it could incorrectly cache
  NXDOMAIN responses, as if they were valid, for records proven by NSEC or
  NSEC3 to exist. A remote attacker could use this flaw to cause a BIND
  server to return the bogus, cached NXDOMAIN responses for valid records and
  prevent users from retrieving those records (denial of service).
  (CVE-2010-0097)

  The original fix for CVE-2009-4022 was found to be incomplete. BIND was
  incorrectly caching certain responses without performing proper DNSSEC
  validation. CNAME and DNAME records could be cached, without proper DNSSEC
  validation, when received from processing recursive client queries that
  requested DNSSEC records but indicated that checking should be disabled. A
  remote attacker could use this flaw to bypass the DNSSEC validation check
  and perform a cache poisoning attack if the target BIND server was
  receiving such client queries. (CVE-2010-0290)

  All BIND users are advised to upgrade to these updated packages, which
  contain a backported patch to resolve these issues. After installing the
  update, the BIND daemon (named) will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.6~4.P1.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.3.6~4.P1.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.3.6~4.P1.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libbind-devel", rpm:"bind-libbind-devel~9.3.6~4.P1.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.3.6~4.P1.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.3.6~4.P1.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.3.6~4.P1.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"caching-nameserver", rpm:"caching-nameserver~9.3.6~4.P1.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
