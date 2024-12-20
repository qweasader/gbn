# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.1011024911442100");
  script_cve_id("CVE-2024-9427");
  script_tag(name:"creation_date", value:"2024-10-24 04:08:58 +0000 (Thu, 24 Oct 2024)");
  script_version("2024-10-25T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-10-25 05:05:38 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-ef4911442d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ef4911442d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ef4911442d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316304");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'koji' package(s) announced via the FEDORA-2024-ef4911442d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.35.1. Includes fix for CVE-2024-9427");

  script_tag(name:"affected", value:"'koji' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"koji", rpm:"koji~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koji-builder", rpm:"koji-builder~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koji-builder-plugins", rpm:"koji-builder-plugins~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koji-hub", rpm:"koji-hub~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koji-hub-plugins", rpm:"koji-hub-plugins~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koji-utils", rpm:"koji-utils~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koji-vm", rpm:"koji-vm~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koji-web", rpm:"koji-web~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-koji", rpm:"python3-koji~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-koji-cli-plugins", rpm:"python3-koji-cli-plugins~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-koji-hub", rpm:"python3-koji-hub~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-koji-hub-plugins", rpm:"python3-koji-hub-plugins~1.35.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-koji-web", rpm:"python3-koji-web~1.35.1~1.fc39", rls:"FC39"))) {
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
