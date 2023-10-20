# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130120");
  script_cve_id("CVE-2015-4456");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:57 +0000 (Thu, 15 Oct 2015)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0256)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0256");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0256.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16106");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-009");
  script_xref(name:"URL", value:"https://owncloud.org/changelog/desktop/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'owncloud-client' package(s) announced via the MGASA-2015-0256 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ownCloud Desktop Client before 1.8.2 was vulnerable against MITM attacks when
used in combination with self-signed certificates (CVE-2015-4456).

The owncloud-client package has been updated to version 1.8.3, which fixes this
issue as well as several other bugs");

  script_tag(name:"affected", value:"'owncloud-client' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ocsync1", rpm:"lib64ocsync1~1.8.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64owncloud-client-devel", rpm:"lib64owncloud-client-devel~1.8.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64owncloudsync1", rpm:"lib64owncloudsync1~1.8.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libocsync1", rpm:"libocsync1~1.8.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libowncloud-client-devel", rpm:"libowncloud-client-devel~1.8.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libowncloudsync1", rpm:"libowncloudsync1~1.8.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"owncloud-client", rpm:"owncloud-client~1.8.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ocsync1", rpm:"lib64ocsync1~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64owncloud-client-devel", rpm:"lib64owncloud-client-devel~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64owncloudsync1", rpm:"lib64owncloudsync1~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libocsync1", rpm:"libocsync1~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libowncloud-client-devel", rpm:"libowncloud-client-devel~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libowncloudsync1", rpm:"libowncloudsync1~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"owncloud-client", rpm:"owncloud-client~1.8.3~1.mga5", rls:"MAGEIA5"))) {
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
