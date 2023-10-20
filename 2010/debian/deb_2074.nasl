# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67829");
  script_cve_id("CVE-2010-0001");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2074)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2074");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2074");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2074");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ncompress' package(s) announced via the DSA-2074 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aki Helin discovered an integer underflow in ncompress, the original Lempel-Ziv compress/uncompress programs. This could lead to the execution of arbitrary code when trying to decompress a crafted LZW compressed gzip archive.

For the stable distribution (lenny), this problem has been fixed in version 4.2.4.2-1+lenny1.

For the testing (squeeze) and unstable (sid) distribution, this problem has been fixed in version 4.2.4.3-1.

We recommend that you upgrade your ncompress package.");

  script_tag(name:"affected", value:"'ncompress' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"ncompress", ver:"4.2.4.2-1+lenny1", rls:"DEB5"))) {
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
