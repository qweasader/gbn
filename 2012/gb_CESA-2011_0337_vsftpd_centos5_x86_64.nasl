# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017402.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881289");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:18:45 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-0762");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2011:0337");
  script_name("CentOS Update for vsftpd CESA-2011:0337 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vsftpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"vsftpd on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"vsftpd (Very Secure File Transfer Protocol (FTP) daemon) is a secure FTP
  server for Linux, UNIX, and similar operating systems.

  A flaw was discovered in the way vsftpd processed file name patterns. An
  FTP user could use this flaw to cause the vsftpd process to use an
  excessive amount of CPU time, when processing a request with a
  specially-crafted file name pattern. (CVE-2011-0762)

  All vsftpd users should upgrade to this updated package, which contains a
  backported patch to correct this issue. The vsftpd daemon must be restarted
  for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"vsftpd", rpm:"vsftpd~2.0.5~16.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
