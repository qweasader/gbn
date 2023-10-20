# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0287");
  script_cve_id("CVE-2014-0250", "CVE-2014-0791");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0287)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0287");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0287.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2014-07/msg00008.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13444");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the MGASA-2014-0287 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated freerdp packages fix security vulnerabilities:

Integer overflows in memory allocations in client/X11/xf_graphics.c in FreeRDP
through 1.0.2 allows remote RDP servers to have an unspecified impact through
unspecified vectors (CVE-2014-0250).

Integer overflow in the license_read_scope_list function in
libfreerdp/core/license.c in FreeRDP through 1.0.2 allows remote RDP servers
to cause a denial of service (application crash) or possibly have unspecified
other impact via a large ScopeCount value in a Scope List in a Server License
Request packet (CVE-2014-0791).");

  script_tag(name:"affected", value:"'freerdp' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~1.0.1~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~1.0.1~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp1", rpm:"lib64freerdp1~1.0.1~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~1.0.1~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp1", rpm:"libfreerdp1~1.0.1~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~1.0.2~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~1.0.2~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp1", rpm:"lib64freerdp1~1.0.2~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~1.0.2~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp1", rpm:"libfreerdp1~1.0.2~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
