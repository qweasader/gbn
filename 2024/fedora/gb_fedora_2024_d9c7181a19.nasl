# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10099971819719");
  script_cve_id("CVE-2024-5187");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-25T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-10-25 05:05:38 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 13:36:11 +0000 (Wed, 23 Oct 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-d9c7181a19)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-d9c7181a19");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-d9c7181a19");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290806");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290807");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'onnx' package(s) announced via the FEDORA-2024-d9c7181a19 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2024-5187");

  script_tag(name:"affected", value:"'onnx' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"onnx", rpm:"onnx~1.14.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onnx-debuginfo", rpm:"onnx-debuginfo~1.14.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onnx-debugsource", rpm:"onnx-debugsource~1.14.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onnx-devel", rpm:"onnx-devel~1.14.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onnx-libs", rpm:"onnx-libs~1.14.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onnx-libs-debuginfo", rpm:"onnx-libs-debuginfo~1.14.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-onnx", rpm:"python3-onnx~1.14.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-onnx-debuginfo", rpm:"python3-onnx-debuginfo~1.14.1~3.fc40", rls:"FC40"))) {
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
