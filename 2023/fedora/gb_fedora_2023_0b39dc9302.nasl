# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885180");
  script_cve_id("CVE-2023-5218", "CVE-2023-5346", "CVE-2023-5472", "CVE-2023-5473", "CVE-2023-5474", "CVE-2023-5475", "CVE-2023-5476", "CVE-2023-5477", "CVE-2023-5478", "CVE-2023-5479", "CVE-2023-5481", "CVE-2023-5483", "CVE-2023-5484", "CVE-2023-5485", "CVE-2023-5486", "CVE-2023-5487");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:23 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 15:50:51 +0000 (Thu, 12 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-0b39dc9302)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-0b39dc9302");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-0b39dc9302");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242073");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242074");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246173");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246174");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246427");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2023-0b39dc9302 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 118.0.5993.117. Security release for CVE-2023-5472

----

Update to 118.0.5993.88

----

Update to 118.0.5993.70. Include following security fixes:

 - CVE-2023-5218: Use after free in Site Isolation.
 - CVE-2023-5487: Inappropriate implementation in Fullscreen.
 - CVE-2023-5484: Inappropriate implementation in Navigation.
 - CVE-2023-5475: Inappropriate implementation in DevTools.
 - CVE-2023-5483: Inappropriate implementation in Intents.
 - CVE-2023-5481: Inappropriate implementation in Downloads.
 - CVE-2023-5476: Use after free in Blink History.
 - CVE-2023-5474: Heap buffer overflow in PDF.
 - CVE-2023-5479: Inappropriate implementation in Extensions API.
 - CVE-2023-5485: Inappropriate implementation in Autofill.
 - CVE-2023-5478: Inappropriate implementation in Autofill.
 - CVE-2023-5477: Inappropriate implementation in Installer.
 - CVE-2023-5486: Inappropriate implementation in Input.
 - CVE-2023-5473: Use after free in Cast.


----

update to 117.0.5938.149.");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~118.0.5993.117~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~118.0.5993.117~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~118.0.5993.117~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~118.0.5993.117~1.fc39", rls:"FC39"))) {
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
