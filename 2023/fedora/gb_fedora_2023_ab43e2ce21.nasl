# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885108");
  script_tag(name:"creation_date", value:"2023-10-31 02:14:20 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-ab43e2ce21)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-ab43e2ce21");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-ab43e2ce21");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238648");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241851");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-altree-bigfloat, golang-github-seancfoley-bintree, golang-github-seancfoley-ipaddress, kitty' package(s) announced via the FEDORA-2023-ab43e2ce21 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"rebuild against golang-x-image 0.13.0

----

version 0.30.1

----

fix overflow when GLFW_IM_MODULE=ibus is set and ibus is not running

----

split out kitten

clarify licenses for subpackages");

  script_tag(name:"affected", value:"'golang-github-altree-bigfloat, golang-github-seancfoley-bintree, golang-github-seancfoley-ipaddress, kitty' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-altree-bigfloat", rpm:"golang-github-altree-bigfloat~0.2.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-altree-bigfloat-devel", rpm:"golang-github-altree-bigfloat-devel~0.2.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-seancfoley-bintree", rpm:"golang-github-seancfoley-bintree~1.2.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-seancfoley-bintree-devel", rpm:"golang-github-seancfoley-bintree-devel~1.2.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-seancfoley-ipaddress", rpm:"golang-github-seancfoley-ipaddress~1.5.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-seancfoley-ipaddress-devel", rpm:"golang-github-seancfoley-ipaddress-devel~1.5.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty", rpm:"kitty~0.30.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-debuginfo", rpm:"kitty-debuginfo~0.30.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-debugsource", rpm:"kitty-debugsource~0.30.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-doc", rpm:"kitty-doc~0.30.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-kitten", rpm:"kitty-kitten~0.30.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-kitten-debuginfo", rpm:"kitty-kitten-debuginfo~0.30.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-shell-integration", rpm:"kitty-shell-integration~0.30.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-terminfo", rpm:"kitty-terminfo~0.30.1~2.fc39", rls:"FC39"))) {
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
