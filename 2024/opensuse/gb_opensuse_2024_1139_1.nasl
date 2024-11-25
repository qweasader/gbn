# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856047");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-22655", "CVE-2023-28746", "CVE-2023-38575", "CVE-2023-39368", "CVE-2023-43490");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-04-09 01:06:25 +0000 (Tue, 09 Apr 2024)");
  script_name("openSUSE: Security Advisory for ucode (SUSE-SU-2024:1139-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeapMicro5\.3|openSUSELeap15\.5|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1139-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OIJ4PQ6FAACMKLLE6ZCYDZTBAMETTQFR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode'
  package(s) announced via the SUSE-SU-2024:1139-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

  * Updated to Intel CPU Microcode 20240312 release. (bsc#1221323)

  * CVE-2023-39368: Protection mechanism failure of bus lock regulator for some
      Intel Processors may allow an unauthenticated user to potentially enable
      denial of service via network access

  * CVE-2023-38575: Non-transparent sharing of return predictor targets between
      contexts in some Intel Processors may allow an authorized user to
      potentially enable information disclosure via local access.

  * CVE-2023-28746: Information exposure through microarchitectural state after
      transient execution from some register files for some Intel Atom Processors
      may allow an authenticated user to potentially enable information disclosure
      via local access.

  * CVE-2023-22655 Protection mechanism failure in some 3rd and 4th Generation
      Intel Xeon Processors when using Intel SGX or Intel TDX may allow a
      privileged user to potentially enable escalation of privilege via local
      access.

  * CVE-2023-43490: Incorrect calculation in microcode keying mechanism for some
      Intel Xeon D Processors with Intel� SGX may allow a privileged user to
      potentially enable information disclosure via local access.

  ##");

  script_tag(name:"affected", value:"'ucode' package(s) on openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-20240312", rpm:"ucode-intel-20240312~150200.38.1", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-20240312", rpm:"ucode-intel-20240312~150200.38.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-20240312", rpm:"ucode-intel-20240312~150200.38.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-20240312", rpm:"ucode-intel-20240312~150200.38.1", rls:"openSUSELeapMicro5.4"))) {
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