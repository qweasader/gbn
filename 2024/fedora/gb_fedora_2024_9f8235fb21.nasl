# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886269");
  script_cve_id("CVE-2023-52425");
  script_tag(name:"creation_date", value:"2024-03-25 09:37:31 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-09-13T15:40:36+0000");
  script_tag(name:"last_modification", value:"2024-09-13 15:40:36 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 02:03:16 +0000 (Fri, 09 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-9f8235fb21)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-9f8235fb21");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-9f8235fb21");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-14/");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US/thunderbird/115.9.0/releasenotes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the FEDORA-2024-9f8235fb21 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 115.9.0

* [link moved to references]
* [link moved to references]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~115.9.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~115.9.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-debugsource", rpm:"thunderbird-debugsource~115.9.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-librnp-rnp", rpm:"thunderbird-librnp-rnp~115.9.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-librnp-rnp-debuginfo", rpm:"thunderbird-librnp-rnp-debuginfo~115.9.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-wayland", rpm:"thunderbird-wayland~115.9.0~1.fc39", rls:"FC39"))) {
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
