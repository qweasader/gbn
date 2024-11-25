# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856672");
  script_version("2024-11-07T05:05:35+0000");
  script_cve_id("CVE-2021-47598", "CVE-2024-40909", "CVE-2024-40954", "CVE-2024-41059");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-07 05:05:35 +0000 (Thu, 07 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-28 19:43:58 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-11-01 05:02:37 +0000 (Fri, 01 Nov 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel RT (Live Patch 17 for SLE 15 SP5) (SUSE-SU-2024:3856-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3856-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2LSLV3QQQYIAV376IANSLYZETKMXDLVZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel RT (Live Patch 17 for SLE 15 SP5)'
  package(s) announced via the SUSE-SU-2024:3856-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150500_13_61 fixes several issues.

  The following security issues were fixed:

  * CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init()
      (bsc#1227471).

  * CVE-2024-40954: net: do not leave a dangling sk pointer, when socket
      creation fails (bsc#1227808)

  * CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228573).

  * CVE-2024-40909: bpf: Fix a potential use-after-free in bpf_link_free()
      (bsc#1228349).");

  script_tag(name:"affected", value:"'the Linux Kernel RT (Live Patch 17 for SLE 15 SP5)' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5-RT.Update.17-debugsource-3", rpm:"kernel-livepatch-SLE15-SP5-RT.Update.17-debugsource-3~150500.11.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5.14.21-150500.13.61-rt-3", rpm:"kernel-livepatch-5.14.21-150500.13.61-rt-3~150500.11.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5.14.21-150500.13.61-rt-debuginfo-3", rpm:"kernel-livepatch-5.14.21-150500.13.61-rt-debuginfo-3~150500.11.6.1", rls:"openSUSELeap15.5"))) {
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
