# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0109");
  script_cve_id("CVE-2024-3156", "CVE-2024-3158", "CVE-2024-3159");
  script_tag(name:"creation_date", value:"2024-04-09 04:13:31 +0000 (Tue, 09 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-26 15:59:59 +0000 (Fri, 26 Apr 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0109)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0109");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0109.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33032");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33056");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_23.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_30.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/02/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/02/stable-channel-update-for-desktop_13.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/02/stable-channel-update-for-desktop_20.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/02/stable-channel-update-for-desktop_22.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/02/stable-channel-update-for-desktop_27.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/03/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/03/stable-channel-update-for-desktop_12.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/03/stable-channel-update-for-desktop_19.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/03/stable-channel-update-for-desktop_26.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0109 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
123.0.6312.105 release.
Since the last update 120.0.6099.224, 66 vulnerabilities are fixed,
including:
High CVE-2024-3156: Inappropriate implementation in V8. Reported by
Zhenghang Xiao (@Kipreyyy) on 2024-03-12
High CVE-2024-3158: Use after free in Bookmarks. Reported by undoingfish
on 2024-03-17
High CVE-2024-3159: Out of bounds memory access in V8. Reported by
Edouard Bochin (@le_douds) and Tao Yan (@Ga1ois) of Palo Alto Networks,
via Pwn2Own 2024 on 2024-03-22
More information are available following the links listed as references.
Please, do note, only x86_64 is supported from now on.
i586 support for linux was stopped some years ago and the community is
not able to provide patches anymore for the latest Chromium code.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~123.0.6312.105~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~123.0.6312.105~1.mga9.tainted", rls:"MAGEIA9"))) {
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
