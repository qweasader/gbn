# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0142");
  script_cve_id("CVE-2020-27844", "CVE-2021-21159", "CVE-2021-21160", "CVE-2021-21161", "CVE-2021-21162", "CVE-2021-21163", "CVE-2021-21164", "CVE-2021-21165", "CVE-2021-21166", "CVE-2021-21167", "CVE-2021-21168", "CVE-2021-21169", "CVE-2021-21170", "CVE-2021-21171", "CVE-2021-21172", "CVE-2021-21173", "CVE-2021-21174", "CVE-2021-21175", "CVE-2021-21176", "CVE-2021-21177", "CVE-2021-21178", "CVE-2021-21179", "CVE-2021-21180", "CVE-2021-21181", "CVE-2021-21182", "CVE-2021-21183", "CVE-2021-21184", "CVE-2021-21185", "CVE-2021-21186", "CVE-2021-21187", "CVE-2021-21188", "CVE-2021-21189", "CVE-2021-21190", "CVE-2021-21191", "CVE-2021-21192", "CVE-2021-21193");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-23 19:54:06 +0000 (Tue, 23 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0142)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0142");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0142.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28534");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/03/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/03/stable-channel-update-for-desktop_12.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/03/stable-channel-update-for-desktop_5.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2021-0142 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities. At least one of them
is known to be actively exploited.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 7, Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~89.0.4389.90~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~89.0.4389.90~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~89.0.4389.90~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~89.0.4389.90~1.mga8", rls:"MAGEIA8"))) {
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
