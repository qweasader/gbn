# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-August/016068.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880755");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2009:1206");
  script_cve_id("CVE-2009-2414", "CVE-2009-2416");
  script_name("CentOS Update for libxml CESA-2009:1206 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"libxml on CentOS 3");
  script_tag(name:"insight", value:"libxml is a library for parsing and manipulating XML files. A Document Type
  Definition (DTD) defines the legal syntax (and also which elements can be
  used) for certain types of files, such as XML files.

  A stack overflow flaw was found in the way libxml processes the root XML
  document element definition in a DTD. A remote attacker could provide a
  specially-crafted XML file, which once opened by a local, unsuspecting
  user, would lead to denial of service (application crash). (CVE-2009-2414)

  Multiple use-after-free flaws were found in the way libxml parses the
  Notation and Enumeration attribute types. A remote attacker could provide
  a specially-crafted XML file, which once opened by a local, unsuspecting
  user, would lead to denial of service (application crash). (CVE-2009-2416)

  Users should upgrade to these updated packages, which contain backported
  patches to resolve these issues. For Red Hat Enterprise Linux 3, they
  contain backported patches for the libxml and libxml2 packages. For Red Hat
  Enterprise Linux 4 and 5, they contain backported patches for the libxml2
  packages. The desktop must be restarted (log out, then log back in) for
  this update to take effect.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"libxml", rpm:"libxml~1.8.17~9.3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.5.10~15", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.5.10~15", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.5.10~15", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml-devel", rpm:"libxml-devel~1.8.17~9.3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
