# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0348");
  script_cve_id("CVE-2016-10198", "CVE-2016-10199", "CVE-2017-5840", "CVE-2017-5841", "CVE-2017-5845");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0348)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0348");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0348.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20237");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/02/02/9");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-04/msg00073.html");
  script_xref(name:"URL", value:"https://lwn.net/Alerts/714997/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer0.10-plugins-good, gstreamer1.0-plugins-good' package(s) announced via the MGASA-2017-0348 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A crafted AAC audio file could have caused an invalid read and thus
corruption or denial of service (CVE-2016-10198).

A crafted mp4 file could have caused an invalid read and thus corruption
or denial of service (CVE-2016-10199).

A crafted AVI file could have caused an invalid read and thus corruption
or denial of service (CVE-2017-5840).

A crafted AVI file with metadata tag entries (ncdt) could have caused
invalid read access and thus corruption or denial of service
(CVE-2017-5841).

A crafted AVI file could have caused an invalid read access resulting in
denial of service (CVE-2017-5845).

Note that GStreamer 0.10 was only affected by CVE-2016-10198 and
CVE-2017-5840.");

  script_tag(name:"affected", value:"'gstreamer0.10-plugins-good, gstreamer1.0-plugins-good' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-aalib", rpm:"gstreamer0.10-aalib~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-caca", rpm:"gstreamer0.10-caca~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-dv", rpm:"gstreamer0.10-dv~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-flac", rpm:"gstreamer0.10-flac~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-jack", rpm:"gstreamer0.10-jack~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-good", rpm:"gstreamer0.10-plugins-good~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-pulse", rpm:"gstreamer0.10-pulse~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-raw1394", rpm:"gstreamer0.10-raw1394~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-soup", rpm:"gstreamer0.10-soup~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-speex", rpm:"gstreamer0.10-speex~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-wavpack", rpm:"gstreamer0.10-wavpack~0.10.31~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-aalib", rpm:"gstreamer1.0-aalib~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-caca", rpm:"gstreamer1.0-caca~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dv", rpm:"gstreamer1.0-dv~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-flac", rpm:"gstreamer1.0-flac~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-jack", rpm:"gstreamer1.0-jack~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-good", rpm:"gstreamer1.0-plugins-good~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-pulse", rpm:"gstreamer1.0-pulse~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-raw1394", rpm:"gstreamer1.0-raw1394~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soup", rpm:"gstreamer1.0-soup~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-speex", rpm:"gstreamer1.0-speex~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-vp8", rpm:"gstreamer1.0-vp8~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wavpack", rpm:"gstreamer1.0-wavpack~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
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
