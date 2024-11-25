# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0213");
  script_cve_id("CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1732", "CVE-2014-1733", "CVE-2014-1734", "CVE-2014-1735", "CVE-2014-1736");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0213)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0213");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0213.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2014/04/stable-channel-update_24.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13325");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2920");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2014-0213 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chromium-browser-stable packages fix security vulnerabilities:

A type confusion issue was discovered in the v8 javascript library
(CVE-2014-1730).

John Butler discovered a type confusion issue in the WebKit/Blink document
object model implementation (CVE-2014-1731).

Khalil Zhani discovered a use-after-free issue in the speech recognition
feature (CVE-2014-1732).

Jed Davis discovered a way to bypass the seccomp-bpf sandbox
(CVE-2014-1733).

The Google Chrome development team discovered and fixed multiple issues
with potential security impact (CVE-2014-1734).

The Google Chrome development team discovered and fixed multiple issues
in version 3.24.35.33 of the v8 javascript library (CVE-2014-1735).

SkyLined discovered an integer overflow issue in the v8 javascript
library (CVE-2014-1736).");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~34.0.1847.132~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~34.0.1847.132~2.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~34.0.1847.132~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~34.0.1847.132~2.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~34.0.1847.132~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~34.0.1847.132~2.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~34.0.1847.132~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~34.0.1847.132~2.mga4.tainted", rls:"MAGEIA4"))) {
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
