# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0209");
  script_cve_id("CVE-2017-18198", "CVE-2017-18199", "CVE-2017-18201");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-31 10:29:00 +0000 (Wed, 31 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0209)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0209");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0209.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22740");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/NHBEK7JWO4GCS73UAOQOUFGTMIIMYYTR/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcdio' package(s) announced via the MGASA-2018-0209 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap corruption bug was found in the way libcdio handled processing of
ISO files. An attacker could potentially use this flaw to crash
applications using libcdio by tricking them into processing crafted ISO
files, thus resulting in local DoS (CVE-2017-18198).

A NULL pointer dereference flaw was found in the way libcdio handled
processing of ISO files. An attacker could potentially use this flaw to
crash applications using libcdio by tricking them into processing
crafted ISO files (CVE-2017-18199).

A double-free flaw was found in the way libcdio handled processing of
ISO files. An attacker could potentially use this flaw to crash
applications using libcdio by tricking them into processing crafted ISO
files (CVE-2017-18201).");

  script_tag(name:"affected", value:"'libcdio' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64cdio++0", rpm:"lib64cdio++0~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cdio-devel", rpm:"lib64cdio-devel~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cdio-static-devel", rpm:"lib64cdio-static-devel~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cdio16", rpm:"lib64cdio16~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64iso9660_10", rpm:"lib64iso9660_10~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64udf0", rpm:"lib64udf0~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio++0", rpm:"libcdio++0~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio", rpm:"libcdio~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio-apps", rpm:"libcdio-apps~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio-devel", rpm:"libcdio-devel~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio-static-devel", rpm:"libcdio-static-devel~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio16", rpm:"libcdio16~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiso9660_10", rpm:"libiso9660_10~0.94~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudf0", rpm:"libudf0~0.94~1.1.mga6", rls:"MAGEIA6"))) {
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
