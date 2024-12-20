# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885217");
  script_cve_id("CVE-2023-26116", "CVE-2023-26117", "CVE-2023-26118");
  script_tag(name:"creation_date", value:"2023-11-05 02:21:18 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-30 17:17:24 +0000 (Tue, 30 May 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-035866b576)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-035866b576");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-035866b576");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2208177");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2208185");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2208195");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icecat' package(s) announced via the FEDORA-2023-035866b576 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Release 115.3.1");

  script_tag(name:"affected", value:"'icecat' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"icecat", rpm:"icecat~115.3.1~7.rh2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icecat-debuginfo", rpm:"icecat-debuginfo~115.3.1~7.rh2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icecat-debugsource", rpm:"icecat-debugsource~115.3.1~7.rh2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icecat-wayland", rpm:"icecat-wayland~115.3.1~7.rh2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icecat-x11", rpm:"icecat-x11~115.3.1~7.rh2.fc39", rls:"FC39"))) {
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
