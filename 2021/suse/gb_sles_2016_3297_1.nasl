# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3297.1");
  script_cve_id("CVE-2016-9445", "CVE-2016-9446", "CVE-2016-9809", "CVE-2016-9812", "CVE-2016-9813");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3297-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3297-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163297-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-bad' package(s) announced via the SUSE-SU-2016:3297-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-bad fixes the following issues:
- CVE-2016-9809: Malicious mkv/h264 file could cause an off by one out of
 bounds read and lead to crash (bsc#1013659)
- CVE-2016-9812: Malicious mpeg file could cause invalid a null pointer
 access and lead to crash (bsc#1013678)
- CVE-2016-9813: Malicious mpegts file could cause invalid a null pointer
 access and lead to crash (bsc#1013680)
- CVE-2016-9445, CVE-2016-9446: Check an integer overflow and initialize a
 buffer in vmncdec (bsc#1010829)");

  script_tag(name:"affected", value:"'gstreamer-plugins-bad' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad", rpm:"gstreamer-plugins-bad~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debuginfo", rpm:"gstreamer-plugins-bad-debuginfo~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debugsource", rpm:"gstreamer-plugins-bad-debugsource~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-lang", rpm:"gstreamer-plugins-bad-lang~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0", rpm:"libgstbasecamerabinsrc-1_0-0~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-debuginfo~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0", rpm:"libgstcodecparsers-1_0-0~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-debuginfo", rpm:"libgstcodecparsers-1_0-0-debuginfo~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstegl-1_0-0", rpm:"libgstegl-1_0-0~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstegl-1_0-0-debuginfo", rpm:"libgstegl-1_0-0-debuginfo~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0", rpm:"libgstmpegts-1_0-0~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-debuginfo", rpm:"libgstmpegts-1_0-0-debuginfo~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0", rpm:"libgstphotography-1_0-0~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-debuginfo", rpm:"libgstphotography-1_0-0-debuginfo~1.2.4~3.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libgstegl-1_0-0", rpm:"libgstegl-1_0-0~1.2.4~3.4.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstegl-1_0-0-debuginfo", rpm:"libgstegl-1_0-0-debuginfo~1.2.4~3.4.1", rls:"SLES12.0SP2"))) {
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
