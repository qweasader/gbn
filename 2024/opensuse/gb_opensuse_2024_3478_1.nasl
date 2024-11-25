# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856521");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2017-15865", "CVE-2022-37032", "CVE-2024-44070");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-22 15:03:00 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-09-30 04:00:27 +0000 (Mon, 30 Sep 2024)");
  script_name("openSUSE: Security Advisory for quagga (SUSE-SU-2024:3478-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3478-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UVZ6ERSN5V63IGZLHDTYOHAZWMZUKHHP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga'
  package(s) announced via the SUSE-SU-2024:3478-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for quagga fixes the following issues:

  * CVE-2017-15865: sensitive information disclosed when malformed BGP UPDATE
      packets are processed. (bsc#1230866)

  * CVE-2024-44070: crash when parsing Tunnel Encap attribute due to no length
      check. (bsc#1229438)

  * CVE-2022-37032: out-of-bounds read when parsing a BGP capability message due
      to incorrect size check. (bsc#1202023)");

  script_tag(name:"affected", value:"'quagga' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0-debuginfo", rpm:"libospfapiclient0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0-debuginfo", rpm:"libquagga_pb0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1-debuginfo", rpm:"libzebra1-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debugsource", rpm:"quagga-debugsource~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0-debuginfo", rpm:"libospf0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0-debuginfo", rpm:"libfpm_pb0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0-debuginfo", rpm:"libospfapiclient0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0-debuginfo", rpm:"libquagga_pb0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1-debuginfo", rpm:"libzebra1-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debugsource", rpm:"quagga-debugsource~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0-debuginfo", rpm:"libospf0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0-debuginfo", rpm:"libfpm_pb0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0-debuginfo", rpm:"libospfapiclient0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0-debuginfo", rpm:"libquagga_pb0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1-debuginfo", rpm:"libzebra1-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debugsource", rpm:"quagga-debugsource~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0-debuginfo", rpm:"libospf0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0-debuginfo", rpm:"libfpm_pb0-debuginfo~1.1.1~150400.12.8.1", rls:"openSUSELeap15.5"))) {
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