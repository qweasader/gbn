# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881850");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-23 12:46:06 +0530 (Mon, 23 Dec 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for ca-certificates CESA-2013:1866 centos6");

  script_tag(name:"affected", value:"ca-certificates on CentOS 6");
  script_tag(name:"insight", value:"This package contains the set of CA certificates chosen by the Mozilla
Foundation for use with the Internet Public Key Infrastructure (PKI).

It was found that a subordinate Certificate Authority (CA) mis-issued an
intermediate certificate, which could be used to conduct man-in-the-middle
attacks. This update renders that particular intermediate certificate as
untrusted. (BZ#1038894)

All users should upgrade to this updated package. After installing the
update, all applications using the ca-certificates package must be
restarted for the changes to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1866");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-December/020087.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ca-certificates'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"ca-certificates", rpm:"ca-certificates~2013.1.95~65.1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
