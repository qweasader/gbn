# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856373");
  script_version("2024-08-23T05:05:37+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:08:35 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for fwupdate (SUSE-SU-2024:1867-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1867-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6I3ISB44NQMHLEYKKBLNDCWVXWFPXWVH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fwupdate'
  package(s) announced via the SUSE-SU-2024:1867-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of fwupdate fixes the following issues:

  * rebuild the package with the new secure boot key (bsc#1209188).

  * Update the email address of security team in SBAT (bsc#1221301)

  * elf_aarch64_efi.lds: set the memory permission explicitly to avoid ld
      warning like 'LOAD segment with RWX permissions'

  ##");

  script_tag(name:"affected", value:"'fwupdate' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-12", rpm:"fwupdate-12~150100.11.15.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwup1-debuginfo-12", rpm:"libfwup1-debuginfo-12~150100.11.15.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-efi-12", rpm:"fwupdate-efi-12~150100.11.15.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-debuginfo-12", rpm:"fwupdate-debuginfo-12~150100.11.15.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-debugsource-12", rpm:"fwupdate-debugsource-12~150100.11.15.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-efi-debuginfo-12", rpm:"fwupdate-efi-debuginfo-12~150100.11.15.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwup1-12", rpm:"libfwup1-12~150100.11.15.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-devel-12", rpm:"fwupdate-devel-12~150100.11.15.2", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-12", rpm:"fwupdate-12~150100.11.15.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwup1-debuginfo-12", rpm:"libfwup1-debuginfo-12~150100.11.15.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-efi-12", rpm:"fwupdate-efi-12~150100.11.15.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-debuginfo-12", rpm:"fwupdate-debuginfo-12~150100.11.15.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-debugsource-12", rpm:"fwupdate-debugsource-12~150100.11.15.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-efi-debuginfo-12", rpm:"fwupdate-efi-debuginfo-12~150100.11.15.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwup1-12", rpm:"libfwup1-12~150100.11.15.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdate-devel-12", rpm:"fwupdate-devel-12~150100.11.15.2", rls:"openSUSELeap15.5"))) {
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