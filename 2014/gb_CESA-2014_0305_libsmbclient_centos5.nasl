# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881903");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-20 09:46:01 +0530 (Thu, 20 Mar 2014)");
  script_cve_id("CVE-2013-0213", "CVE-2013-0214", "CVE-2013-4124");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for libsmbclient CESA-2014:0305 centos5");

  script_tag(name:"affected", value:"libsmbclient on CentOS 5");
  script_tag(name:"insight", value:"Samba is an open-source implementation of the Server Message Block (SMB) or
Common Internet File System (CIFS) protocol, which allows PC-compatible
machines to share files, printers, and other information.

It was discovered that the Samba Web Administration Tool (SWAT) did not
protect against being opened in a web page frame. A remote attacker could
possibly use this flaw to conduct a clickjacking attack against SWAT users
or users with an active SWAT session. (CVE-2013-0213)

A flaw was found in the Cross-Site Request Forgery (CSRF) protection
mechanism implemented in SWAT. An attacker with the knowledge of a victim's
password could use this flaw to bypass CSRF protections and conduct a CSRF
attack against the victim SWAT user. (CVE-2013-0214)

An integer overflow flaw was found in the way Samba handled an Extended
Attribute (EA) list provided by a client. A malicious client could send a
specially crafted EA list that triggered an overflow, causing the server to
loop and reprocess the list using an excessive amount of memory.
(CVE-2013-4124)

Note: This issue did not affect the default configuration of the Samba
server.

Red Hat would like to thank the Samba project for reporting CVE-2013-0213
and CVE-2013-0214. Upstream acknowledges Jann Horn as the original reporter
of CVE-2013-0213 and CVE-2013-0214.

All users of Samba are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the smb service will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0305");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-March/020204.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsmbclient'
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

  if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.0.33~3.40.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.0.33~3.40.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.33~3.40.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.33~3.40.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.33~3.40.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.33~3.40.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}