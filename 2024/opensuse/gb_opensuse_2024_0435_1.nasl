# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833190");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2017-5849");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-17 13:55:33 +0000 (Fri, 17 Mar 2017)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:23 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for netpbm (SUSE-SU-2024:0435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0435-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Q2DF7MBXY7TEHGEVCSSQJMPVYHCUBKSC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netpbm'
  package(s) announced via the SUSE-SU-2024:0435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netpbm fixes the following issues:

  * CVE-2017-5849: Fixed out-of-bound read and write issue that can occur in
      function putgreytile() and put1bitbwtile() (bsc#1022790, bsc#1022791).

  ##");

  script_tag(name:"affected", value:"'netpbm' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-debugsource", rpm:"netpbm-debugsource~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11", rpm:"libnetpbm11~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-debuginfo", rpm:"libnetpbm11-debuginfo~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm-devel", rpm:"libnetpbm-devel~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-vulnerable-debuginfo", rpm:"netpbm-vulnerable-debuginfo~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-debuginfo", rpm:"netpbm-debuginfo~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-vulnerable", rpm:"netpbm-vulnerable~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-32bit", rpm:"libnetpbm11-32bit~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-32bit-debuginfo", rpm:"libnetpbm11-32bit-debuginfo~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-debugsource", rpm:"netpbm-debugsource~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11", rpm:"libnetpbm11~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-debuginfo", rpm:"libnetpbm11-debuginfo~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm-devel", rpm:"libnetpbm-devel~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-vulnerable-debuginfo", rpm:"netpbm-vulnerable-debuginfo~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-debuginfo", rpm:"netpbm-debuginfo~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-vulnerable", rpm:"netpbm-vulnerable~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-32bit", rpm:"libnetpbm11-32bit~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-32bit-debuginfo", rpm:"libnetpbm11-32bit-debuginfo~10.80.1~150000.3.14.1", rls:"openSUSELeap15.5"))) {
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