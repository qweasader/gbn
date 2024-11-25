# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0194");
  script_cve_id("CVE-2024-5157", "CVE-2024-5158", "CVE-2024-5159", "CVE-2024-5160");
  script_tag(name:"creation_date", value:"2024-05-27 04:12:12 +0000 (Mon, 27 May 2024)");
  script_version("2024-05-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-05-27 05:05:23 +0000 (Mon, 27 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0194");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0194.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33231");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0194 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
125.0.6422.76 release. It includes 6 security fixes
Please, do note, that since some versions ago, only x86_64 is supported.
i586 support for linux was stopped some years ago and the community is
not able to provide patches anymore for the latest Chromium code..
High CVE-2024-5157: Use after free in Scheduling.
High CVE-2024-5158: Type Confusion in V8.
High CVE-2024-5159: Heap buffer overflow in ANGLE.
High CVE-2024-5160: Heap buffer overflow in Dawn.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~125.0.6422.76~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~125.0.6422.76~1.mga9.tainted", rls:"MAGEIA9"))) {
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
