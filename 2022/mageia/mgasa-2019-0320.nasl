# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0320");
  script_cve_id("CVE-2019-13699", "CVE-2019-13700", "CVE-2019-13701", "CVE-2019-13702", "CVE-2019-13703", "CVE-2019-13704", "CVE-2019-13705", "CVE-2019-13706", "CVE-2019-13707", "CVE-2019-13708", "CVE-2019-13709", "CVE-2019-13710", "CVE-2019-13711", "CVE-2019-13713", "CVE-2019-13714", "CVE-2019-13715", "CVE-2019-13716", "CVE-2019-13717", "CVE-2019-13718", "CVE-2019-13719", "CVE-2019-13720", "CVE-2019-13721");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0320)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0320");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0320.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25655");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/10/stable-channel-update-for-desktop_22.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/10/stable-channel-update-for-desktop_31.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2019-0320 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 78.0.3904.87 fixes security issues:

Multiple flaws were found in the way Chromium 77.0.3865.120 processes
various types of web content, where loading a web page containing malicious
content could cause Chromium to crash, execute arbitrary code, or disclose
sensitive information. (CVE-2019-13699, CVE-2019-13700, CVE-2019-13701,
CVE-2019-13702, CVE-2019-13703, CVE-2019-13704, CVE-2019-13705,
CVE-2019-13706, CVE-2019-13707, CVE-2019-13708, CVE-2019-13709,
CVE-2019-13710, CVE-2019-13711, CVE-2019-13713, CVE-2019-13714,
CVE-2019-13715, CVE-2019-13716, CVE-2019-13717, CVE-2019-13718,
CVE-2019-13719, CVE-2019-13720, CVE-2019-13721)");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~78.0.3904.87~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~78.0.3904.87~1.mga7", rls:"MAGEIA7"))) {
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
