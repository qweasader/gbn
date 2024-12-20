# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885659");
  script_cve_id("CVE-2023-6679", "CVE-2024-1086", "CVE-2024-23849");
  script_tag(name:"creation_date", value:"2024-02-06 02:03:35 +0000 (Tue, 06 Feb 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-2116a8468b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2116a8468b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-2116a8468b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253986");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253987");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260041");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260043");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262126");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262128");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-headers' package(s) announced via the FEDORA-2024-2116a8468b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The 6.7.3 stable kernel rebase contains new features, improved hardware support, and a number of important fixes across the tree.");

  script_tag(name:"affected", value:"'kernel, kernel-headers' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bpftool-debuginfo", rpm:"bpftool-debuginfo~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-core", rpm:"kernel-core~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-cross-headers", rpm:"kernel-cross-headers~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-core", rpm:"kernel-debug-core~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-matched", rpm:"kernel-debug-devel-matched~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules", rpm:"kernel-debug-modules~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-core", rpm:"kernel-debug-modules-core~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-extra", rpm:"kernel-debug-modules-extra~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-internal", rpm:"kernel-debug-modules-internal~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-uki-virt", rpm:"kernel-debug-uki-virt~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-aarch64", rpm:"kernel-debuginfo-common-aarch64~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-ppc64le", rpm:"kernel-debuginfo-common-ppc64le~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-s390x", rpm:"kernel-debuginfo-common-s390x~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-matched", rpm:"kernel-devel-matched~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules", rpm:"kernel-modules~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-core", rpm:"kernel-modules-core~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-extra", rpm:"kernel-modules-extra~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-internal", rpm:"kernel-modules-internal~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-selftests-internal", rpm:"kernel-selftests-internal~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uki-virt", rpm:"kernel-uki-virt~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf", rpm:"libperf~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf-devel", rpm:"libperf-devel~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf-debuginfo", rpm:"python3-perf-debuginfo~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtla", rpm:"rtla~6.7.3~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rv", rpm:"rv~6.7.3~200.fc39", rls:"FC39"))) {
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
