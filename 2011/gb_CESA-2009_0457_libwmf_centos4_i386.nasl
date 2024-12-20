# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015922.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880898");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0457");
  script_cve_id("CVE-2009-1364");
  script_name("CentOS Update for libwmf CESA-2009:0457 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwmf'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"libwmf on CentOS 4");
  script_tag(name:"insight", value:"libwmf is a library for reading and converting Windows Metafile Format
  (WMF) vector graphics. libwmf is used by applications such as GIMP and
  ImageMagick.

  A pointer use-after-free flaw was found in the GD graphics library embedded
  in libwmf. An attacker could create a specially-crafted WMF file that would
  cause an application using libwmf to crash or, potentially, execute
  arbitrary code as the user running the application when opened by a victim.
  (CVE-2009-1364)

  Note: This flaw is specific to the GD graphics library embedded in libwmf.
  It does not affect the GD graphics library from the 'gd' packages, or
  applications using it.

  Red Hat would like to thank Tavis Ormandy of the Google Security Team for
  responsibly reporting this flaw.

  All users of libwmf are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  update, all applications using libwmf must be restarted for the update
  to take effect.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8.3~5.8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwmf-devel", rpm:"libwmf-devel~0.2.8.3~5.8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
