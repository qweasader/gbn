# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0423");
  script_cve_id("CVE-2017-15386", "CVE-2017-15387", "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391", "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395", "CVE-2017-15396", "CVE-2017-15398", "CVE-2017-15399", "CVE-2017-15406", "CVE-2017-5111", "CVE-2017-5112", "CVE-2017-5113", "CVE-2017-5114", "CVE-2017-5115", "CVE-2017-5116", "CVE-2017-5117", "CVE-2017-5118", "CVE-2017-5119", "CVE-2017-5120", "CVE-2017-5121", "CVE-2017-5122", "CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127", "CVE-2017-5128", "CVE-2017-5129", "CVE-2017-5130", "CVE-2017-5131", "CVE-2017-5132", "CVE-2017-5133");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-07 19:22:00 +0000 (Wed, 07 Nov 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0423)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0423");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0423.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21670");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/08/stable-channel-update-for-desktop_24.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/09/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/09/stable-channel-update-for-desktop_14.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/09/stable-channel-update-for-desktop_21.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/10/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/10/stable-channel-update-for-desktop_26.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/11/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/11/stable-channel-update-for-desktop_13.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2017-0423 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 62.0.3202.94 fixes security issues:
Multiple flaws were found in the way Chromium 60 processes various types
of web content, where loading a web page containing malicious content
could cause Chromium to crash, execute arbitrary code, or disclose
sensitive information. (CVE-2017-5111, CVE-2017-5112, CVE-2017-5113,
CVE-2017-5114, CVE-2017-5115, CVE-2017-5116, CVE-2017-5117,
CVE-2017-5118, CVE-2017-5119, CVE-2017-5120, CVE-2017-5121,
CVE-2017-5122, CVE-2017-5124, CVE-2017-5125, CVE-2017-5126,
CVE-2017-5127, CVE-2017-5128, CVE-2017-5129, CVE-2017-5130,
CVE-2017-5131, CVE-2017-5132, CVE-2017-5133, CVE-2017-15386,
CVE-2017-15387, CVE-2017-15388, CVE-2017-15389, CVE-2017-15390,
CVE-2017-15391, CVE-2017-15392, CVE-2017-15393, CVE-2017-15394,
CVE-2017-15395, CVE-2017-15396, CVE-2017-15398, CVE-2017-15399,
CVE-2017-15406)");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~62.0.3202.94~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~62.0.3202.94~1.mga6", rls:"MAGEIA6"))) {
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
