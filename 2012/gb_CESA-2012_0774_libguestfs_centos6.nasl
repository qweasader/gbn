# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only



if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018710.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881146");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:22:13 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2690");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"CESA", value:"2012:0774");
  script_name("CentOS Update for libguestfs CESA-2012:0774 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libguestfs'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"libguestfs on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"libguestfs is a library for accessing and modifying guest disk images.

  It was found that editing files with virt-edit left said files in a
  world-readable state (and did not preserve the file owner or
  Security-Enhanced Linux context). If an administrator on the host used
  virt-edit to edit a file inside a guest, the file would be left with
  world-readable permissions. This could lead to unprivileged guest users
  accessing files they would otherwise be unable to. (CVE-2012-2690)

  These updated libguestfs packages include numerous bug fixes and
  enhancements. Space precludes documenting all of these changes in this
  advisory. Users are directed to the Red Hat Enterprise Linux 6.3 Technical
  Notes for information on the most significant of these changes.

  Users of libguestfs are advised to upgrade to these updated packages, which
  fix these issues and add these enhancements.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-devel", rpm:"libguestfs-devel~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-java", rpm:"libguestfs-java~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-java-devel", rpm:"libguestfs-java-devel~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-javadoc", rpm:"libguestfs-javadoc~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-tools", rpm:"libguestfs-tools~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-tools-c", rpm:"libguestfs-tools-c~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-libguestfs", rpm:"ocaml-libguestfs~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-libguestfs-devel", rpm:"ocaml-libguestfs-devel~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Sys-Guestfs", rpm:"perl-Sys-Guestfs~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libguestfs", rpm:"python-libguestfs~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libguestfs", rpm:"ruby-libguestfs~1.16.19~1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
