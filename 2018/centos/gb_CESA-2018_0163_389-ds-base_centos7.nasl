# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882838");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-26 07:46:40 +0100 (Fri, 26 Jan 2018)");
  script_cve_id("CVE-2017-15134");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-15 21:29:00 +0000 (Wed, 15 May 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for 389-ds-base CESA-2018:0163 centos7");
  script_tag(name:"summary", value:"Check the version of 389-ds-base");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3
(LDAPv3) compliant server. The base packages include the Lightweight Directory
Access Protocol (LDAP) server and command-line utilities for server administration.

Security Fix(es):

  * A stack buffer overflow flaw was found in the way 389-ds-base handled
certain LDAP search filters. A remote, unauthenticated attacker could
potentially use this flaw to make ns-slapd crash via a specially crafted
LDAP request, thus resulting in denial of service. (CVE-2017-15134)

Bug Fix(es):

  * Previously, when a connection received a high operation rate, Directory
Server stopped to poll the connection in certain situations. As a
consequence, new requests on the connection were not detected and
processed. With this update, Directory Server correctly decides whether a
connection has to be polled. As a result, connections with a high request
rate no longer remain unprocessed. (BZ#1523505)

  * Previously, if Directory Server was stopped during an operation which
created additional changes in the memory changelog, the Replication Update
Vector (RUV) in the changelog was higher than the RUV in the database. As a
consequence, Directory Server recreated the changelog when the server
started. With this update, the server now writes the highest RUV to the
changelog only if there is the highest Change Sequence Number (CSN) present
in it. As a result, the database and the changelog RUV are consistent and
the server does not need recreating the changelog at start up. (BZ#1523507)

  * Due to a bug, using a large number of Class of Service (CoS) templates in
Directory Server increased the virtual attribute processing time. This
update improves the structure of the CoS storage. As a result, using a
large number of CoS templates no longer increases the virtual attribute
processing time. (BZ#1526928)");
  script_tag(name:"affected", value:"389-ds-base on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2018:0163");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-January/022719.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.6.1~26.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.6.1~26.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.6.1~26.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.3.6.1~26.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
