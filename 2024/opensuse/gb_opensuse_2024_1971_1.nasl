# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856210");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-31950", "CVE-2024-31951", "CVE-2024-34088");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-12 04:00:36 +0000 (Wed, 12 Jun 2024)");
  script_name("openSUSE: Security Advisory for frr (SUSE-SU-2024:1971-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1971-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/D77H4Z3VCEI5GVZGOSUPNENNGT55PVUV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'frr'
  package(s) announced via the SUSE-SU-2024:1971-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for frr fixes the following issues:

  * CVE-2024-34088: Fixed null pointer via get_edge() function can trigger a
      denial of service (bsc#1223786).

  * CVE-2024-31951: Fixed buffer overflow in ospf_te_parse_ext_link
      (bsc#1222528).

  * CVE-2024-31950: Fixed buffer overflow and daemon crash in ospf_te_parse_ri
      (bsc#1222526).

  ##");

  script_tag(name:"affected", value:"'frr' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libfrr0", rpm:"libfrr0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0-debuginfo", rpm:"libfrrcares0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0-debuginfo", rpm:"libfrrospfapiclient0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debugsource", rpm:"frr-debugsource~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0", rpm:"libfrr_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0", rpm:"libfrrzmq0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0-debuginfo", rpm:"libfrrzmq0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0", rpm:"libfrrcares0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0", rpm:"libfrrfpm_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0", rpm:"libfrrospfapiclient0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0-debuginfo", rpm:"libfrr_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0", rpm:"libfrrsnmp0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr", rpm:"frr~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0-debuginfo", rpm:"libfrr0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0-debuginfo", rpm:"libfrrfpm_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0", rpm:"libmlag_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0-debuginfo", rpm:"libfrrsnmp0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debuginfo", rpm:"frr-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-devel", rpm:"frr-devel~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0-debuginfo", rpm:"libmlag_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0", rpm:"libfrr0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0-debuginfo", rpm:"libfrrcares0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0-debuginfo", rpm:"libfrrospfapiclient0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debugsource", rpm:"frr-debugsource~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0", rpm:"libfrr_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0", rpm:"libfrrzmq0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0-debuginfo", rpm:"libfrrzmq0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0", rpm:"libfrrcares0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0", rpm:"libfrrfpm_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0", rpm:"libfrrospfapiclient0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0-debuginfo", rpm:"libfrr_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0", rpm:"libfrrsnmp0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr", rpm:"frr~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0-debuginfo", rpm:"libfrr0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0-debuginfo", rpm:"libfrrfpm_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0", rpm:"libmlag_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0-debuginfo", rpm:"libfrrsnmp0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debuginfo", rpm:"frr-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-devel", rpm:"frr-devel~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0-debuginfo", rpm:"libmlag_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libfrr0", rpm:"libfrr0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0-debuginfo", rpm:"libfrrcares0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0-debuginfo", rpm:"libfrrospfapiclient0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debugsource", rpm:"frr-debugsource~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0", rpm:"libfrr_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0", rpm:"libfrrzmq0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0-debuginfo", rpm:"libfrrzmq0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0", rpm:"libfrrcares0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0", rpm:"libfrrfpm_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0", rpm:"libfrrospfapiclient0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0-debuginfo", rpm:"libfrr_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0", rpm:"libfrrsnmp0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr", rpm:"frr~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0-debuginfo", rpm:"libfrr0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0-debuginfo", rpm:"libfrrfpm_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0", rpm:"libmlag_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0-debuginfo", rpm:"libfrrsnmp0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debuginfo", rpm:"frr-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-devel", rpm:"frr-devel~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0-debuginfo", rpm:"libmlag_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0", rpm:"libfrr0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0-debuginfo", rpm:"libfrrcares0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0-debuginfo", rpm:"libfrrospfapiclient0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debugsource", rpm:"frr-debugsource~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0", rpm:"libfrr_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0", rpm:"libfrrzmq0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0-debuginfo", rpm:"libfrrzmq0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0", rpm:"libfrrcares0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0", rpm:"libfrrfpm_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0", rpm:"libfrrospfapiclient0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0-debuginfo", rpm:"libfrr_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0", rpm:"libfrrsnmp0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr", rpm:"frr~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0-debuginfo", rpm:"libfrr0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0-debuginfo", rpm:"libfrrfpm_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0", rpm:"libmlag_pb0~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0-debuginfo", rpm:"libfrrsnmp0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debuginfo", rpm:"frr-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-devel", rpm:"frr-devel~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0-debuginfo", rpm:"libmlag_pb0-debuginfo~8.4~150500.4.23.1", rls:"openSUSELeap15.5"))) {
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