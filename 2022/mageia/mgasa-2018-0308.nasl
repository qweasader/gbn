# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0308");
  script_cve_id("CVE-2018-6148", "CVE-2018-6149");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-02 13:30:13 +0000 (Tue, 02 Jul 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0308)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0308");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0308.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23153");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/06/stable-channel-update-for-desktop_12.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2018-0308 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 67.0.3396.87-2 fixes an out-of-bounds write error in V8
(CVE-2018-6149) and incorrect handling of content security policy
(CVE-2018-6148). It also contains a new google API key.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~67.0.3396.87~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~67.0.3396.87~2.mga6", rls:"MAGEIA6"))) {
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
