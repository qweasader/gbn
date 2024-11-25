# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856063");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2024-28182", "CVE-2024-2818");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-04-10 01:06:11 +0000 (Wed, 10 Apr 2024)");
  script_name("openSUSE: Security Advisory for nghttp2 (SUSE-SU-2024:1167-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeapMicro5\.3|openSUSELeap15\.5|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1167-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VPYUF6CAWSJABMV2ZJ4TWMRNZVVK5XIA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nghttp2'
  package(s) announced via the SUSE-SU-2024:1167-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nghttp2 fixes the following issues:

  * CVE-2024-28182: Fixed denial of service via http/2 continuation frames
      (bsc#1221399)

  ##");

  script_tag(name:"affected", value:"'nghttp2' package(s) on openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-debuginfo", rpm:"libnghttp2-14-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14", rpm:"libnghttp2-14~1.40.0~150200.17.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debugsource", rpm:"nghttp2-debugsource~1.40.0~150200.17.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debuginfo", rpm:"nghttp2-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-python-debugsource", rpm:"nghttp2-python-debugsource~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14", rpm:"libnghttp2-14~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-debuginfo", rpm:"libnghttp2-14-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-debuginfo", rpm:"libnghttp2_asio1-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1", rpm:"libnghttp2_asio1~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2", rpm:"nghttp2~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debugsource", rpm:"nghttp2-debugsource~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debuginfo", rpm:"nghttp2-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio-devel", rpm:"libnghttp2_asio-devel~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nghttp2", rpm:"python3-nghttp2~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nghttp2-debuginfo", rpm:"python3-nghttp2-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-devel", rpm:"libnghttp2-devel~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit", rpm:"libnghttp2-14-32bit~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-32bit", rpm:"libnghttp2_asio1-32bit~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-32bit-debuginfo", rpm:"libnghttp2_asio1-32bit-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit-debuginfo", rpm:"libnghttp2-14-32bit-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-python-debugsource", rpm:"nghttp2-python-debugsource~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14", rpm:"libnghttp2-14~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-debuginfo", rpm:"libnghttp2-14-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-debuginfo", rpm:"libnghttp2_asio1-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1", rpm:"libnghttp2_asio1~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2", rpm:"nghttp2~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debugsource", rpm:"nghttp2-debugsource~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debuginfo", rpm:"nghttp2-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio-devel", rpm:"libnghttp2_asio-devel~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nghttp2", rpm:"python3-nghttp2~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nghttp2-debuginfo", rpm:"python3-nghttp2-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-devel", rpm:"libnghttp2-devel~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit", rpm:"libnghttp2-14-32bit~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-32bit", rpm:"libnghttp2_asio1-32bit~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-32bit-debuginfo", rpm:"libnghttp2_asio1-32bit-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit-debuginfo", rpm:"libnghttp2-14-32bit-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-debuginfo", rpm:"libnghttp2-14-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14", rpm:"libnghttp2-14~1.40.0~150200.17.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debugsource", rpm:"nghttp2-debugsource~1.40.0~150200.17.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debuginfo", rpm:"nghttp2-debuginfo~1.40.0~150200.17.1", rls:"openSUSELeapMicro5.4"))) {
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