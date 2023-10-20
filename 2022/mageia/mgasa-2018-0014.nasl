# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0014");
  script_cve_id("CVE-2017-5846", "CVE-2017-5847");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-20 19:01:00 +0000 (Fri, 20 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0014");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0014.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20239");
  script_xref(name:"URL", value:"https://lwn.net/Alerts/714998/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3821");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer0.10-plugins-ugly, gstreamer1.0-plugins-ugly' package(s) announced via the MGASA-2018-0014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Boeck discovered multiple vulnerabilities in the GStreamer media
framework and its codecs and demuxers, which may result in denial of
service or the execution of arbitrary code if a malformed media file is
opened (CVE-2017-5846, CVE-2017-5847).");

  script_tag(name:"affected", value:"'gstreamer0.10-plugins-ugly, gstreamer1.0-plugins-ugly' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-a52dec", rpm:"gstreamer0.10-a52dec~0.10.19~14.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-a52dec", rpm:"gstreamer0.10-a52dec~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-amrnb", rpm:"gstreamer0.10-amrnb~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-amrwbdec", rpm:"gstreamer0.10-amrwbdec~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-cdio", rpm:"gstreamer0.10-cdio~0.10.19~14.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-cdio", rpm:"gstreamer0.10-cdio~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-lame", rpm:"gstreamer0.10-lame~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mpeg", rpm:"gstreamer0.10-mpeg~0.10.19~14.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-mpeg", rpm:"gstreamer0.10-mpeg~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-ugly", rpm:"gstreamer0.10-plugins-ugly~0.10.19~14.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-ugly", rpm:"gstreamer0.10-plugins-ugly~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-sid", rpm:"gstreamer0.10-sid~0.10.19~14.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-sid", rpm:"gstreamer0.10-sid~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-twolame", rpm:"gstreamer0.10-twolame~0.10.19~14.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-twolame", rpm:"gstreamer0.10-twolame~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-x264", rpm:"gstreamer0.10-x264~0.10.19~14.2.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-a52dec", rpm:"gstreamer1.0-a52dec~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-a52dec", rpm:"gstreamer1.0-a52dec~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-amrnb", rpm:"gstreamer1.0-amrnb~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-amrwbdec", rpm:"gstreamer1.0-amrwbdec~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdio", rpm:"gstreamer1.0-cdio~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdio", rpm:"gstreamer1.0-cdio~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-lame", rpm:"gstreamer1.0-lame~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg", rpm:"gstreamer1.0-mpeg~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg", rpm:"gstreamer1.0-mpeg~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-ugly", rpm:"gstreamer1.0-plugins-ugly~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-ugly", rpm:"gstreamer1.0-plugins-ugly~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sid", rpm:"gstreamer1.0-sid~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sid", rpm:"gstreamer1.0-sid~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-twolame", rpm:"gstreamer1.0-twolame~1.4.3~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-twolame", rpm:"gstreamer1.0-twolame~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-x264", rpm:"gstreamer1.0-x264~1.4.3~2.1.mga5.tainted", rls:"MAGEIA5"))) {
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
