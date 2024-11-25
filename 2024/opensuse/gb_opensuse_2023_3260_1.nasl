# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833575");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-2727", "CVE-2023-2728");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 19:11:59 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:20:06 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for kubernetes1.24 (SUSE-SU-2023:3260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3260-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RBV5PR77EFFYFQXWKEBH6EG67XTFZJVW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.24'
  package(s) announced via the SUSE-SU-2023:3260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubernetes1.24 fixes the following issues:

  Update to version 1.24.16:

  * CVE-2023-2727: Fixed bypassing policies imposed by the ImagePolicyWebhook
      admission plugin(bsc#1211630).

  * CVE-2023-2728: Fixed bypassing enforce mountable secrets policy imposed by
      the ServiceAccount admission plugin (bsc#1211631).

  ##");

  script_tag(name:"affected", value:"'kubernetes1.24' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-controller-manager", rpm:"kubernetes1.24-controller-manager~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubelet-common", rpm:"kubernetes1.24-kubelet-common~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client", rpm:"kubernetes1.24-client~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-proxy", rpm:"kubernetes1.24-proxy~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-scheduler", rpm:"kubernetes1.24-scheduler~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-common", rpm:"kubernetes1.24-client-common~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubeadm", rpm:"kubernetes1.24-kubeadm~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubelet", rpm:"kubernetes1.24-kubelet~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-apiserver", rpm:"kubernetes1.24-apiserver~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-fish-completion", rpm:"kubernetes1.24-client-fish-completion~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-bash-completion", rpm:"kubernetes1.24-client-bash-completion~1.24.16~150400.9.8.2##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-controller-manager", rpm:"kubernetes1.24-controller-manager~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubelet-common", rpm:"kubernetes1.24-kubelet-common~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client", rpm:"kubernetes1.24-client~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-proxy", rpm:"kubernetes1.24-proxy~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-scheduler", rpm:"kubernetes1.24-scheduler~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-common", rpm:"kubernetes1.24-client-common~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubeadm", rpm:"kubernetes1.24-kubeadm~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubelet", rpm:"kubernetes1.24-kubelet~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-apiserver", rpm:"kubernetes1.24-apiserver~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-fish-completion", rpm:"kubernetes1.24-client-fish-completion~1.24.16~150400.9.8.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-bash-completion", rpm:"kubernetes1.24-client-bash-completion~1.24.16~150400.9.8.2##", rls:"openSUSELeap15.4"))) {
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