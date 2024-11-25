# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0046");
  script_cve_id("CVE-2016-9957", "CVE-2016-9958", "CVE-2016-9959", "CVE-2016-9960", "CVE-2016-9961");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-15 19:50:42 +0000 (Thu, 15 Jun 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0046)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0046");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0046.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2016-0428.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20177");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'audacious-plugins' package(s) announced via the MGASA-2017-0046 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Evans discovered that incorrect emulation of the SPC700 audio
co-processor of the Super Nintendo Entertainment System allows the
execution of arbitrary code if a malformed SPC music file is opened
(CVE-2016-9957, CVE-2016-9958, CVE-2016-9959, CVE-2016-9960,
CVE-2016-9961).

These issues were previously fixed in MGASA-2016-0428 in the
game-music-emu library, but audacious-plugins contains a decoder built
with a bundled copy, which has been patched to fix the issues.");

  script_tag(name:"affected", value:"'audacious-plugins' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"audacious-adplug", rpm:"audacious-adplug~3.5.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-adplug", rpm:"audacious-adplug~3.5.2~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-fluidsynth", rpm:"audacious-fluidsynth~3.5.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-fluidsynth", rpm:"audacious-fluidsynth~3.5.2~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-jack", rpm:"audacious-jack~3.5.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-jack", rpm:"audacious-jack~3.5.2~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-plugins", rpm:"audacious-plugins~3.5.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-plugins", rpm:"audacious-plugins~3.5.2~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-pulse", rpm:"audacious-pulse~3.5.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-pulse", rpm:"audacious-pulse~3.5.2~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-sid", rpm:"audacious-sid~3.5.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-sid", rpm:"audacious-sid~3.5.2~2.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-wavpack", rpm:"audacious-wavpack~3.5.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audacious-wavpack", rpm:"audacious-wavpack~3.5.2~2.1.mga5.tainted", rls:"MAGEIA5"))) {
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
