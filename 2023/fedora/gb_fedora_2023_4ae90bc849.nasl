# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884799");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:26 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-4ae90bc849)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-4ae90bc849");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-4ae90bc849");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-rustls-webpki' package(s) announced via the FEDORA-2023-4ae90bc849 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to version 0.100.2.

This includes a fix for RUSTSEC-2023-0053 (denial-of-service via crafted certificate chains).");

  script_tag(name:"affected", value:"'rust-rustls-webpki' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-webpki+alloc-devel", rpm:"rust-rustls-webpki+alloc-devel~0.100.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-webpki+default-devel", rpm:"rust-rustls-webpki+default-devel~0.100.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-webpki+std-devel", rpm:"rust-rustls-webpki+std-devel~0.100.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-webpki", rpm:"rust-rustls-webpki~0.100.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-webpki-devel", rpm:"rust-rustls-webpki-devel~0.100.2~1.fc39", rls:"FC39"))) {
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
