# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0784.1");
  script_cve_id("CVE-2018-5146");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-09 14:55:15 +0000 (Thu, 09 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0784-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0784-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180784-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvorbis' package(s) announced via the SUSE-SU-2018:0784-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvorbis fixes the following issues:
- CVE-2018-5146: Fixed out of bounds memory write while processing Vorbis
 audio data (bsc#1085687).");

  script_tag(name:"affected", value:"'libvorbis' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-debugsource", rpm:"libvorbis-debugsource~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-doc", rpm:"libvorbis-doc~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0", rpm:"libvorbis0~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-32bit", rpm:"libvorbis0-32bit~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-debuginfo", rpm:"libvorbis0-debuginfo~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-debuginfo-32bit", rpm:"libvorbis0-debuginfo-32bit~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2", rpm:"libvorbisenc2~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-32bit", rpm:"libvorbisenc2-32bit~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-debuginfo", rpm:"libvorbisenc2-debuginfo~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-debuginfo-32bit", rpm:"libvorbisenc2-debuginfo-32bit~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3", rpm:"libvorbisfile3~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-32bit", rpm:"libvorbisfile3-32bit~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-debuginfo", rpm:"libvorbisfile3-debuginfo~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-debuginfo-32bit", rpm:"libvorbisfile3-debuginfo-32bit~1.3.3~10.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-debugsource", rpm:"libvorbis-debugsource~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-doc", rpm:"libvorbis-doc~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0", rpm:"libvorbis0~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-32bit", rpm:"libvorbis0-32bit~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-debuginfo", rpm:"libvorbis0-debuginfo~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-debuginfo-32bit", rpm:"libvorbis0-debuginfo-32bit~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2", rpm:"libvorbisenc2~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-32bit", rpm:"libvorbisenc2-32bit~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-debuginfo", rpm:"libvorbisenc2-debuginfo~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-debuginfo-32bit", rpm:"libvorbisenc2-debuginfo-32bit~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3", rpm:"libvorbisfile3~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-32bit", rpm:"libvorbisfile3-32bit~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-debuginfo", rpm:"libvorbisfile3-debuginfo~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-debuginfo-32bit", rpm:"libvorbisfile3-debuginfo-32bit~1.3.3~10.6.1", rls:"SLES12.0SP3"))) {
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
