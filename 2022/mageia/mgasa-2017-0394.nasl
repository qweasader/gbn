# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0394");
  script_cve_id("CVE-2017-7500", "CVE-2017-7501");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2017-0394)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0394");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0394.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21942");
  script_xref(name:"URL", value:"http://rpm.org/wiki/Releases/4.13.0.2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1450369");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1452133");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpm' package(s) announced via the MGASA-2017-0394 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that rpm did not properly handle RPM installations when a
destination path was a symbolic link to a directory, possibly changing
ownership and permissions of an arbitrary directory, and RPM files being
placed in an arbitrary destination. An attacker, with write access to a
directory in which a subdirectory will be installed, could redirect that
directory to an arbitrary location and gain root privilege
(CVE-2017-7500).

It was found that rpm uses temporary files with predictable names when
installing an RPM. An attacker with ability to write in a directory
where files will be installed could create symbolic links to an
arbitrary location and modify content, and possibly permissions to
arbitrary files, which could be used for denial of service or possibly
privilege escalation (CVE-2017-7501)");

  script_tag(name:"affected", value:"'rpm' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64rpm-devel", rpm:"lib64rpm-devel~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpm7", rpm:"lib64rpm7~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpmbuild7", rpm:"lib64rpmbuild7~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpmsign7", rpm:"lib64rpmsign7~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpm-devel", rpm:"librpm-devel~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpm7", rpm:"librpm7~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpmbuild7", rpm:"librpmbuild7~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpmsign7", rpm:"librpmsign7~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rpm", rpm:"python2-rpm~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rpm", rpm:"python3-rpm~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-apidocs", rpm:"rpm-apidocs~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sign", rpm:"rpm-sign~4.13.0.2~3.1.mga6", rls:"MAGEIA6"))) {
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
