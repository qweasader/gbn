# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856516");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2024-45615", "CVE-2024-45616", "CVE-2024-45617", "CVE-2024-45618", "CVE-2024-45619", "CVE-2024-45620", "CVE-2024-8443");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-23 23:26:14 +0000 (Mon, 23 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-27 04:00:23 +0000 (Fri, 27 Sep 2024)");
  script_name("openSUSE: Security Advisory for opensc (SUSE-SU-2024:3444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3444-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/44AR353VYHSA7SVXWQ2SF5235RLMMAOE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc'
  package(s) announced via the SUSE-SU-2024:3444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opensc fixes the following issues:

  * CVE-2024-45620: Incorrect handling of the length of buffers or files in
      pkcs15init. (bsc#1230076)

  * CVE-2024-45619: Incorrect handling length of buffers or files in libopensc.
      (bsc#1230075)

  * CVE-2024-45618: Uninitialized values after incorrect or missing checking
      return values of functions in pkcs15init. (bsc#1230074)

  * CVE-2024-45617: Uninitialized values after incorrect or missing checking
      return values of functions in libopensc. (bsc#1230073)

  * CVE-2024-45616: Uninitialized values after incorrect check or usage of APDU
      response values in libopensc. (bsc#1230072)

  * CVE-2024-45615: Usage of uninitialized values in libopensc and pkcs15init.
      (bsc#1230071)

  * CVE-2024-8443: Heap buffer overflow in OpenPGP driver when generating key.
      (bsc#1230364)");

  script_tag(name:"affected", value:"'opensc' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensc-debugsource", rpm:"opensc-debugsource~0.22.0~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.22.0~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.22.0~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-32bit-debuginfo", rpm:"opensc-32bit-debuginfo~0.22.0~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-32bit", rpm:"opensc-32bit~0.22.0~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-64bit", rpm:"opensc-64bit~0.22.0~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-64bit-debuginfo", rpm:"opensc-64bit-debuginfo~0.22.0~150600.11.3.1", rls:"openSUSELeap15.6"))) {
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