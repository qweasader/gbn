# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881801");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-15 13:02:57 +0530 (Tue, 15 Oct 2013)");
  script_cve_id("CVE-2013-4397");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for libtar CESA-2013:1418 centos6");

  script_tag(name:"affected", value:"libtar on CentOS 6");
  script_tag(name:"insight", value:"The libtar package contains a C library for manipulating tar archives. The
library supports both the strict POSIX tar format and many of the commonly
used GNU extensions.

Two heap-based buffer overflow flaws were found in the way libtar handled
certain archives. If a user were tricked into expanding a specially-crafted
archive, it could cause the libtar executable or an application using
libtar to crash or, potentially, execute arbitrary code. (CVE-2013-4397)

Note: This issue only affected 32-bit builds of libtar.

Red Hat would like to thank Timo Warns for reporting this issue.

All libtar users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1418");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-October/019969.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtar'
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

  if ((res = isrpmvuln(pkg:"libtar", rpm:"libtar~1.2.11~17.el6_4.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtar-devel", rpm:"libtar-devel~1.2.11~17.el6_4.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
