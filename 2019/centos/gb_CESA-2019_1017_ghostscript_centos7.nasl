# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883047");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2019-3839", "CVE-2019-6116");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 14:31:00 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-05-14 02:00:32 +0000 (Tue, 14 May 2019)");
  script_name("CentOS Update for ghostscript CESA-2019:1017 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:1017");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-May/023301.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the CESA-2019:1017 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Ghostscript suite contains utilities for rendering PostScript and PDF
documents. Ghostscript translates PostScript code to common bitmap formats
so that the code can be displayed or printed.

Security Fix(es):

  * ghostscript: missing attack vector protections for CVE-2019-6116
(CVE-2019-3839)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'ghostscript' package(s) on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.07~31.el7_6.11", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-cups", rpm:"ghostscript-cups~9.07~31.el7_6.11", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.07~31.el7_6.11", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.07~31.el7_6.11", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~9.07~31.el7_6.11", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
