# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833097");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-49933", "CVE-2023-49936", "CVE-2023-49937", "CVE-2023-49938");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 17:17:34 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:51:24 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for slurm_22_05 (SUSE-SU-2024:0283-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.5|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0283-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CJALYJ4RLBCURQEMJMSPKNTTDYV6GBL2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm_22_05'
  package(s) announced via the SUSE-SU-2024:0283-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm_22_05 fixes the following issues:

  Update to slurm 22.05.11:

  Security fixes:

  * CVE-2023-49933: Prevent message extension attacks that could bypass the
      message hash. (bsc#1218046)

  * CVE-2023-49936: Prevent NULL pointer dereference on `size_valp` overflow.
      (bsc#1218050)

  * CVE-2023-49937: Prevent double-xfree() on error in
      `_unpack_node_reg_resp()`. (bsc#1218051)

  * CVE-2023-49938: Prevent modified `sbcast` RPCs from opening a file with the
      wrong group permissions. (bsc#1218053)

  Other fixes:

  * Add missing service file for slurmrestd (bsc#1217711).

  * Fix slurm upgrading to incompatible versions (bsc#1216869).

  ##");

  script_tag(name:"affected", value:"'slurm_22_05' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-pam_slurm", rpm:"slurm_22_05-pam_slurm~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-pam_slurm-debuginfo", rpm:"slurm_22_05-pam_slurm-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-slurmdbd", rpm:"slurm_22_05-slurmdbd~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-torque", rpm:"slurm_22_05-torque~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-devel", rpm:"slurm_22_05-devel~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-slurmdbd-debuginfo", rpm:"slurm_22_05-slurmdbd-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-munge-debuginfo", rpm:"slurm_22_05-munge-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-torque-debuginfo", rpm:"slurm_22_05-torque-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-debugsource", rpm:"slurm_22_05-debugsource~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-rest", rpm:"slurm_22_05-rest~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-hdf5", rpm:"slurm_22_05-hdf5~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sjstat", rpm:"slurm_22_05-sjstat~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_22_05", rpm:"perl-slurm_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_22_05", rpm:"libpmi0_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_22_05-debuginfo", rpm:"perl-slurm_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_22_05-debuginfo", rpm:"libnss_slurm2_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sql-debuginfo", rpm:"slurm_22_05-sql-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-cray", rpm:"slurm_22_05-cray~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-lua-debuginfo", rpm:"slurm_22_05-lua-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sql", rpm:"slurm_22_05-sql~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-seff", rpm:"slurm_22_05-seff~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-lua", rpm:"slurm_22_05-lua~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-cray-debuginfo", rpm:"slurm_22_05-cray-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05", rpm:"slurm_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-auth-none", rpm:"slurm_22_05-auth-none~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-plugins-debuginfo", rpm:"slurm_22_05-plugins-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm38-debuginfo", rpm:"libslurm38-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-rest-debuginfo", rpm:"slurm_22_05-rest-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sview-debuginfo", rpm:"slurm_22_05-sview-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-auth-none-debuginfo", rpm:"slurm_22_05-auth-none-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm38", rpm:"libslurm38~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-munge", rpm:"slurm_22_05-munge~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sview", rpm:"slurm_22_05-sview~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-plugins", rpm:"slurm_22_05-plugins~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-openlava", rpm:"slurm_22_05-openlava~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_22_05", rpm:"libnss_slurm2_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-hdf5-debuginfo", rpm:"slurm_22_05-hdf5-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-node-debuginfo", rpm:"slurm_22_05-node-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-debuginfo", rpm:"slurm_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-node", rpm:"slurm_22_05-node~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-testsuite", rpm:"slurm_22_05-testsuite~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_22_05-debuginfo", rpm:"libpmi0_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-config-man", rpm:"slurm_22_05-config-man~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-config", rpm:"slurm_22_05-config~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-webdoc", rpm:"slurm_22_05-webdoc~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-doc", rpm:"slurm_22_05-doc~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-pam_slurm", rpm:"slurm_22_05-pam_slurm~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-pam_slurm-debuginfo", rpm:"slurm_22_05-pam_slurm-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-slurmdbd", rpm:"slurm_22_05-slurmdbd~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-torque", rpm:"slurm_22_05-torque~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-devel", rpm:"slurm_22_05-devel~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-slurmdbd-debuginfo", rpm:"slurm_22_05-slurmdbd-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-munge-debuginfo", rpm:"slurm_22_05-munge-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-torque-debuginfo", rpm:"slurm_22_05-torque-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-debugsource", rpm:"slurm_22_05-debugsource~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-rest", rpm:"slurm_22_05-rest~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-hdf5", rpm:"slurm_22_05-hdf5~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sjstat", rpm:"slurm_22_05-sjstat~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_22_05", rpm:"perl-slurm_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_22_05", rpm:"libpmi0_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_22_05-debuginfo", rpm:"perl-slurm_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_22_05-debuginfo", rpm:"libnss_slurm2_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sql-debuginfo", rpm:"slurm_22_05-sql-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-cray", rpm:"slurm_22_05-cray~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-lua-debuginfo", rpm:"slurm_22_05-lua-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sql", rpm:"slurm_22_05-sql~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-seff", rpm:"slurm_22_05-seff~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-lua", rpm:"slurm_22_05-lua~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-cray-debuginfo", rpm:"slurm_22_05-cray-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05", rpm:"slurm_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-auth-none", rpm:"slurm_22_05-auth-none~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-plugins-debuginfo", rpm:"slurm_22_05-plugins-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm38-debuginfo", rpm:"libslurm38-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-rest-debuginfo", rpm:"slurm_22_05-rest-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sview-debuginfo", rpm:"slurm_22_05-sview-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-auth-none-debuginfo", rpm:"slurm_22_05-auth-none-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm38", rpm:"libslurm38~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-munge", rpm:"slurm_22_05-munge~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sview", rpm:"slurm_22_05-sview~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-plugins", rpm:"slurm_22_05-plugins~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-openlava", rpm:"slurm_22_05-openlava~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_22_05", rpm:"libnss_slurm2_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-hdf5-debuginfo", rpm:"slurm_22_05-hdf5-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-node-debuginfo", rpm:"slurm_22_05-node-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-debuginfo", rpm:"slurm_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-node", rpm:"slurm_22_05-node~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-testsuite", rpm:"slurm_22_05-testsuite~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_22_05-debuginfo", rpm:"libpmi0_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-config-man", rpm:"slurm_22_05-config-man~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-config", rpm:"slurm_22_05-config~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-webdoc", rpm:"slurm_22_05-webdoc~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-doc", rpm:"slurm_22_05-doc~22.05.11~150300.7.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-pam_slurm", rpm:"slurm_22_05-pam_slurm~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-pam_slurm-debuginfo", rpm:"slurm_22_05-pam_slurm-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-slurmdbd", rpm:"slurm_22_05-slurmdbd~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-torque", rpm:"slurm_22_05-torque~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-devel", rpm:"slurm_22_05-devel~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-slurmdbd-debuginfo", rpm:"slurm_22_05-slurmdbd-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-munge-debuginfo", rpm:"slurm_22_05-munge-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-torque-debuginfo", rpm:"slurm_22_05-torque-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-debugsource", rpm:"slurm_22_05-debugsource~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-rest", rpm:"slurm_22_05-rest~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-hdf5", rpm:"slurm_22_05-hdf5~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sjstat", rpm:"slurm_22_05-sjstat~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_22_05", rpm:"perl-slurm_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_22_05", rpm:"libpmi0_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_22_05-debuginfo", rpm:"perl-slurm_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_22_05-debuginfo", rpm:"libnss_slurm2_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sql-debuginfo", rpm:"slurm_22_05-sql-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-cray", rpm:"slurm_22_05-cray~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-lua-debuginfo", rpm:"slurm_22_05-lua-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sql", rpm:"slurm_22_05-sql~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-seff", rpm:"slurm_22_05-seff~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-lua", rpm:"slurm_22_05-lua~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-cray-debuginfo", rpm:"slurm_22_05-cray-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05", rpm:"slurm_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-auth-none", rpm:"slurm_22_05-auth-none~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-plugins-debuginfo", rpm:"slurm_22_05-plugins-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm38-debuginfo", rpm:"libslurm38-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-rest-debuginfo", rpm:"slurm_22_05-rest-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sview-debuginfo", rpm:"slurm_22_05-sview-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-auth-none-debuginfo", rpm:"slurm_22_05-auth-none-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm38", rpm:"libslurm38~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-munge", rpm:"slurm_22_05-munge~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sview", rpm:"slurm_22_05-sview~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-plugins", rpm:"slurm_22_05-plugins~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-openlava", rpm:"slurm_22_05-openlava~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_22_05", rpm:"libnss_slurm2_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-hdf5-debuginfo", rpm:"slurm_22_05-hdf5-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-node-debuginfo", rpm:"slurm_22_05-node-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-debuginfo", rpm:"slurm_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-node", rpm:"slurm_22_05-node~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-testsuite", rpm:"slurm_22_05-testsuite~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_22_05-debuginfo", rpm:"libpmi0_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-config-man", rpm:"slurm_22_05-config-man~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-config", rpm:"slurm_22_05-config~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-webdoc", rpm:"slurm_22_05-webdoc~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-doc", rpm:"slurm_22_05-doc~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-pam_slurm", rpm:"slurm_22_05-pam_slurm~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-pam_slurm-debuginfo", rpm:"slurm_22_05-pam_slurm-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-slurmdbd", rpm:"slurm_22_05-slurmdbd~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-torque", rpm:"slurm_22_05-torque~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-devel", rpm:"slurm_22_05-devel~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-slurmdbd-debuginfo", rpm:"slurm_22_05-slurmdbd-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-munge-debuginfo", rpm:"slurm_22_05-munge-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-torque-debuginfo", rpm:"slurm_22_05-torque-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-debugsource", rpm:"slurm_22_05-debugsource~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-rest", rpm:"slurm_22_05-rest~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-hdf5", rpm:"slurm_22_05-hdf5~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sjstat", rpm:"slurm_22_05-sjstat~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_22_05", rpm:"perl-slurm_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_22_05", rpm:"libpmi0_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_22_05-debuginfo", rpm:"perl-slurm_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_22_05-debuginfo", rpm:"libnss_slurm2_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sql-debuginfo", rpm:"slurm_22_05-sql-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-cray", rpm:"slurm_22_05-cray~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-lua-debuginfo", rpm:"slurm_22_05-lua-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sql", rpm:"slurm_22_05-sql~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-seff", rpm:"slurm_22_05-seff~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-lua", rpm:"slurm_22_05-lua~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-cray-debuginfo", rpm:"slurm_22_05-cray-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05", rpm:"slurm_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-auth-none", rpm:"slurm_22_05-auth-none~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-plugins-debuginfo", rpm:"slurm_22_05-plugins-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm38-debuginfo", rpm:"libslurm38-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-rest-debuginfo", rpm:"slurm_22_05-rest-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sview-debuginfo", rpm:"slurm_22_05-sview-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-auth-none-debuginfo", rpm:"slurm_22_05-auth-none-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm38", rpm:"libslurm38~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-munge", rpm:"slurm_22_05-munge~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-sview", rpm:"slurm_22_05-sview~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-plugins", rpm:"slurm_22_05-plugins~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-openlava", rpm:"slurm_22_05-openlava~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_22_05", rpm:"libnss_slurm2_22_05~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-hdf5-debuginfo", rpm:"slurm_22_05-hdf5-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-node-debuginfo", rpm:"slurm_22_05-node-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-debuginfo", rpm:"slurm_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-node", rpm:"slurm_22_05-node~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-testsuite", rpm:"slurm_22_05-testsuite~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_22_05-debuginfo", rpm:"libpmi0_22_05-debuginfo~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-config-man", rpm:"slurm_22_05-config-man~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-config", rpm:"slurm_22_05-config~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-webdoc", rpm:"slurm_22_05-webdoc~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_22_05-doc", rpm:"slurm_22_05-doc~22.05.11~150300.7.9.1", rls:"openSUSELeap15.3"))) {
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