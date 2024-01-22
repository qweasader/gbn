# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704606");
  script_cve_id("CVE-2019-13725", "CVE-2019-13726", "CVE-2019-13727", "CVE-2019-13728", "CVE-2019-13729", "CVE-2019-13730", "CVE-2019-13732", "CVE-2019-13734", "CVE-2019-13735", "CVE-2019-13736", "CVE-2019-13737", "CVE-2019-13738", "CVE-2019-13739", "CVE-2019-13740", "CVE-2019-13741", "CVE-2019-13742", "CVE-2019-13743", "CVE-2019-13744", "CVE-2019-13745", "CVE-2019-13746", "CVE-2019-13747", "CVE-2019-13748", "CVE-2019-13749", "CVE-2019-13750", "CVE-2019-13751", "CVE-2019-13752", "CVE-2019-13753", "CVE-2019-13754", "CVE-2019-13755", "CVE-2019-13756", "CVE-2019-13757", "CVE-2019-13758", "CVE-2019-13759", "CVE-2019-13761", "CVE-2019-13762", "CVE-2019-13763", "CVE-2019-13764", "CVE-2019-13767", "CVE-2020-6377", "CVE-2020-6378", "CVE-2020-6379", "CVE-2020-6380");
  script_tag(name:"creation_date", value:"2020-01-21 04:00:40 +0000 (Tue, 21 Jan 2020)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-13 05:15:00 +0000 (Fri, 13 Mar 2020)");

  script_name("Debian: Security Advisory (DSA-4606-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4606-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4606-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4606");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-4606-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-13725

Gengming Liu and Jianyu Chen discovered a use-after-free issue in the bluetooth implementation.

CVE-2019-13726

Sergei Glazunov discovered a buffer overflow issue.

CVE-2019-13727

@piochu discovered a policy enforcement error.

CVE-2019-13728

Rong Jian and Guang Gong discovered an out-of-bounds write error in the v8 javascript library.

CVE-2019-13729

Zhe Jin discovered a use-after-free issue.

CVE-2019-13730

Soyeon Park and Wen Xu discovered the use of a wrong type in the v8 javascript library.

CVE-2019-13732

Sergei Glazunov discovered a use-after-free issue in the WebAudio implementation.

CVE-2019-13734

Wenxiang Qian discovered an out-of-bounds write issue in the sqlite library.

CVE-2019-13735

Gengming Liu and Zhen Feng discovered an out-of-bounds write issue in the v8 javascript library.

CVE-2019-13736

An integer overflow issue was discovered in the pdfium library.

CVE-2019-13737

Mark Amery discovered a policy enforcement error.

CVE-2019-13738

Johnathan Norman and Daniel Clark discovered a policy enforcement error.

CVE-2019-13739

xisigr discovered a user interface error.

CVE-2019-13740

Khalil Zhani discovered a user interface error.

CVE-2019-13741

Michal Bentkowski discovered that user input could be incompletely validated.

CVE-2019-13742

Khalil Zhani discovered a user interface error.

CVE-2019-13743

Zhiyang Zeng discovered a user interface error.

CVE-2019-13744

Prakash discovered a policy enforcement error.

CVE-2019-13745

Luan Herrera discovered a policy enforcement error.

CVE-2019-13746

David Erceg discovered a policy enforcement error.

CVE-2019-13747

Ivan Popelyshev and Andre Bonatti discovered an uninitialized value.

CVE-2019-13748

David Erceg discovered a policy enforcement error.

CVE-2019-13749

Khalil Zhani discovered a user interface error.

CVE-2019-13750

Wenxiang Qian discovered insufficient validation of data in the sqlite library.

CVE-2019-13751

Wenxiang Qian discovered an uninitialized value in the sqlite library.

CVE-2019-13752

Wenxiang Qian discovered an out-of-bounds read issue in the sqlite library.

CVE-2019-13753

Wenxiang Qian discovered an out-of-bounds read issue in the sqlite library.

CVE-2019-13754

Cody Crews discovered a policy enforcement error.

CVE-2019-13755

Masato Kinugawa discovered a policy enforcement error.

CVE-2019-13756

Khalil Zhani discovered a user interface error.

CVE-2019-13757

Khalil Zhani discovered a user interface error.

CVE-2019-13758

Khalil Zhani discovered a policy enforecement error.

CVE-2019-13759

Wenxu Wu discovered a user interface error.

CVE-2019-13761

Khalil Zhani discovered a user interface error.

CVE-2019-13762

csanuragjain discovered a policy enforecement error.

CVE-2019-13763

weiwangpp93 discovered a policy enforecement error.

CVE-2019-13764

Soyeon Park and Wen ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"79.0.3945.130-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"79.0.3945.130-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"79.0.3945.130-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"79.0.3945.130-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"79.0.3945.130-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"79.0.3945.130-1~deb10u1", rls:"DEB10"))) {
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
