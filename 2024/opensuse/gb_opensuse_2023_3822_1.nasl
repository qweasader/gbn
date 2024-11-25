# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833553");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2022-45154");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:58:26 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:01:01 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for supportutils (SUSE-SU-2023:3822-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3822-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ENUGJKD763NFE6JLZD26BQR2NHN6IUJ3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'supportutils'
  package(s) announced via the SUSE-SU-2023:3822-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for supportutils fixes the following issues:

  Security fixes:

  * CVE-2022-45154: Removed iSCSI passwords (bsc#1207598).

  Other Fixes:

  * Changes in version 3.1.26

  * powerpc plugin to collect the slots and active memory (bsc#1210950)

  * A Cleartext Storage of Sensitive Information vulnerability CVE-2022-45154

  * supportconfig: collect BPF information (pr#154)

  * Added additional iscsi information (pr#155)

  * Added run time detection (bsc#1213127)

  * Changes for supportutils version 3.1.25

  * Removed iSCSI passwords CVE-2022-45154 (bsc#1207598)

  * powerpc: Collect lsslot, amsstat, and opal elogs (pr#149)

  * powerpc: collect invscout logs (pr#150)

  * powerpc: collect RMC status logs (pr#151)

  * Added missing nvme nbft commands (bsc#1211599)

  * Fixed invalid nvme commands (bsc#1211598)

  * Added missing podman information (PED-1703, bsc#1181477)

  * Removed dependency on sysfstools

  * Check for systool use (bsc#1210015)

  * Added selinux checking (bsc#1209979)

  * Updated SLES_VER matrix

  * Fixed missing status detail for apparmor (bsc#1196933)

  * Corrected invalid argument list in docker.txt (bsc#1206608)

  * Applies limit equally to sar data and text files (bsc#1207543)

  * Collects hwinfo hardware logs (bsc#1208928)

  * Collects lparnumascore logs (issue#148)

  * Add dependency to `numactl` on ppc64le and `s390x`, this enforces that
      `numactl --hardware` data is provided in supportconfigs

  * Changes to supportconfig.rc version 3.1.11-35

  * Corrected _sanitize_file to include iscsi.conf and others (bsc#1206402)

  * Changes to supportconfig version 3.1.11-46.4

  * Added plymouth_info

  * Changes to getappcore version 1.53.02

  * The location of chkbin was updated earlier. This documents that change
      (bsc#1205533, bsc#1204942)

  ##");

  script_tag(name:"affected", value:"'supportutils' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"supportutils", rpm:"supportutils~3.1.26~150300.7.35.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils", rpm:"supportutils~3.1.26~150300.7.35.21.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"supportutils", rpm:"supportutils~3.1.26~150300.7.35.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils", rpm:"supportutils~3.1.26~150300.7.35.21.1", rls:"openSUSELeap15.5"))) {
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