# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703599");
  script_cve_id("CVE-2016-2335");
  script_tag(name:"creation_date", value:"2016-06-08 22:00:00 +0000 (Wed, 08 Jun 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-21 20:29:00 +0000 (Thu, 21 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-3599)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3599");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3599");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3599");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'p7zip' package(s) announced via the DSA-3599 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcin Icewall Noga of Cisco Talos discovered an out-of-bound read vulnerability in the CInArchive::ReadFileItem method in p7zip, a 7zr file archiver with high compression ratio. A remote attacker can take advantage of this flaw to cause a denial-of-service or, potentially the execution of arbitrary code with the privileges of the user running p7zip, if a specially crafted UDF file is processed.

For the stable distribution (jessie), this problem has been fixed in version 9.20.1~dfsg.1-4.1+deb8u2.

For the testing distribution (stretch), this problem has been fixed in version 15.14.1+dfsg-2.

For the unstable distribution (sid), this problem has been fixed in version 15.14.1+dfsg-2.

We recommend that you upgrade your p7zip packages.");

  script_tag(name:"affected", value:"'p7zip' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"p7zip", ver:"9.20.1~dfsg.1-4.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"p7zip-full", ver:"9.20.1~dfsg.1-4.1+deb8u2", rls:"DEB8"))) {
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
