# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58690");
  script_cve_id("CVE-2007-3770");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1393)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1393");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1393");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1393");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xfce4-terminal' package(s) announced via the DSA-1393 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that xfce-terminal, a terminal emulator for the xfce environment, did not correctly escape arguments passed to the processes spawned by Open Link. This allowed malicious links to execute arbitrary commands upon the local system.

For the stable distribution (etch), this problem has been fixed in version 0.2.5.6rc1-2etch1.

For the unstable distribution (sid), this problem has been fixed in version 0.2.6-3.

We recommend that you upgrade your xfce4-terminal package.");

  script_tag(name:"affected", value:"'xfce4-terminal' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"xfce4-terminal", ver:"0.2.5.6rc1-2etch1", rls:"DEB4"))) {
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
