# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887231");
  script_cve_id("CVE-2024-26256");
  script_tag(name:"creation_date", value:"2024-06-12 04:13:55 +0000 (Wed, 12 Jun 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-09 17:15:47 +0000 (Tue, 09 Apr 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-b15a51292f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-b15a51292f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-b15a51292f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282529");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the FEDORA-2024-b15a51292f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix for CVE-2024-26256");

  script_tag(name:"affected", value:"'libarchive' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"bsdcat", rpm:"bsdcat~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdcat-debuginfo", rpm:"bsdcat-debuginfo~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdcpio", rpm:"bsdcpio~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdcpio-debuginfo", rpm:"bsdcpio-debuginfo~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar-debuginfo", rpm:"bsdtar-debuginfo~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdunzip", rpm:"bsdunzip~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdunzip-debuginfo", rpm:"bsdunzip-debuginfo~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-debuginfo", rpm:"libarchive-debuginfo~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-debugsource", rpm:"libarchive-debugsource~3.7.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.7.1~2.fc39", rls:"FC39"))) {
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
