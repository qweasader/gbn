# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-September/017012.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880626");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0703");
  script_cve_id("CVE-2010-0405");
  script_name("CentOS Update for bzip2 CESA-2010:0703 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bzip2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"bzip2 on CentOS 5");
  script_tag(name:"insight", value:"bzip2 is a freely available, high-quality data compressor. It provides both
  standalone compression and decompression utilities, as well as a shared
  library for use with other programs.

  An integer overflow flaw was discovered in the bzip2 decompression routine.
  This issue could, when decompressing malformed archives, cause bzip2, or an
  application linked against the libbz2 library, to crash or, potentially,
  execute arbitrary code. (CVE-2010-0405)

  Users of bzip2 should upgrade to these updated packages, which contain a
  backported patch to resolve this issue. All running applications using the
  libbz2 library must be restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"bzip2", rpm:"bzip2~1.0.3~6.el5_5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bzip2-devel", rpm:"bzip2-devel~1.0.3~6.el5_5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bzip2-libs", rpm:"bzip2-libs~1.0.3~6.el5_5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
