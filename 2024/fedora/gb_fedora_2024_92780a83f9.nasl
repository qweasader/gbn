# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886569");
  script_cve_id("CVE-2023-49501", "CVE-2023-49502", "CVE-2023-49528", "CVE-2023-50007", "CVE-2023-50008", "CVE-2023-50009", "CVE-2023-50010", "CVE-2023-51791", "CVE-2023-51792", "CVE-2023-51793", "CVE-2023-51795", "CVE-2023-51796", "CVE-2023-51797", "CVE-2023-51798", "CVE-2024-31578", "CVE-2024-31581", "CVE-2024-31582", "CVE-2024-31585", "CVE-2024-4331", "CVE-2024-4368", "CVE-2024-4558", "CVE-2024-4559");
  script_tag(name:"creation_date", value:"2024-05-27 10:43:04 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-92780a83f9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-92780a83f9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-92780a83f9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274695");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275841");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276116");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276123");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276130");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278765");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278766");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278770");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278771");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279687");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279688");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279690");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-92780a83f9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- update to 124.0.6367.155

 * High CVE-2024-4558: Use after free in ANGLE
 * High CVE-2024-4559: Heap buffer overflow in WebAudio");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~124.0.6367.155~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~124.0.6367.155~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~124.0.6367.155~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~124.0.6367.155~1.fc40", rls:"FC40"))) {
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
