# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892314");
  script_cve_id("CVE-2020-3327", "CVE-2020-3350", "CVE-2020-3481");
  script_tag(name:"creation_date", value:"2020-08-07 03:00:14 +0000 (Fri, 07 Aug 2020)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 08:15:00 +0000 (Thu, 06 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-2314)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2314");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2314");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/clamav");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DLA-2314 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the ClamAV antivirus toolkit:

CVE-2020-3327

An out of bounds read in the ARJ archive-parsing module could cause denial of service. The fix in 0.102.3 was incomplete.

CVE-2020-3350

A malicious user could trick clamscan, clamdscan or clamonacc into moving or removing a different file than intended when those are used with one of the --move or --remove options. This could be used to get rid of special system files.

CVE-2020-3481

The EGG archive module was vulnerable to denial of service via NULL pointer dereference due to improper error handling. The official signature database avoided this problem because the signatures there avoided the use of the EGG archive parser.

For Debian 9 stretch, these problems have been fixed in version 0.102.4+dfsg-0+deb9u1.

We recommend that you upgrade your clamav packages.

For the detailed security status of clamav please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"clamav", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-base", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-docs", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-milter", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamdscan", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav9", ver:"0.102.4+dfsg-0+deb9u1", rls:"DEB9"))) {
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
