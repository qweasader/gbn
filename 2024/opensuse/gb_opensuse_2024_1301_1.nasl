# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856072");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2024-24806", "CVE-2024-27982", "CVE-2024-27983", "CVE-2024-30260", "CVE-2024-30261");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-27 18:34:10 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-04-17 01:01:11 +0000 (Wed, 17 Apr 2024)");
  script_name("openSUSE: Security Advisory for nodejs20 (SUSE-SU-2024:1301-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1301-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AAC4HUDS7SSPUPNK7MT5WUJF3VQJVZPI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20'
  package(s) announced via the SUSE-SU-2024:1301-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs20 fixes the following issues:

  Update to 20.12.1

  Security fixes:

  * CVE-2024-27983: Fixed failed assertion in
      node::http2::Http2Session::~Http2Session() that could lead to HTTP/2 server
      crash (bsc#1222244)

  * CVE-2024-27982: Fixed HTTP Request Smuggling via Content Length Obfuscation
      (bsc#1222384)

  * CVE-2024-30260: Fixed proxy-authorization header not cleared on cross-origin
      redirect in undici (bsc#1222530)

  * CVE-2024-30261: Fixed fetch with integrity option is too lax when algorithm
      is specified but hash value is in incorrect in undici (bsc#1222603)

  * CVE-2024-24806: Fixed improper domain lookup that potentially leads to SSRF
      attacks in libuv (bsc#1220053)

  ##");

  script_tag(name:"affected", value:"'nodejs20' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debugsource", rpm:"nodejs20-debugsource~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"corepack20", rpm:"corepack20~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debuginfo", rpm:"nodejs20-debuginfo~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-devel", rpm:"nodejs20-devel~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm20", rpm:"npm20~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-docs", rpm:"nodejs20-docs~20.12.1~150500.11.9.2##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debugsource", rpm:"nodejs20-debugsource~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"corepack20", rpm:"corepack20~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debuginfo", rpm:"nodejs20-debuginfo~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-devel", rpm:"nodejs20-devel~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm20", rpm:"npm20~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.12.1~150500.11.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-docs", rpm:"nodejs20-docs~20.12.1~150500.11.9.2##", rls:"openSUSELeap15.5"))) {
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