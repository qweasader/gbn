# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63935");
  script_cve_id("CVE-2008-4866", "CVE-2008-5616", "CVE-2009-0385");
  script_tag(name:"creation_date", value:"2009-05-05 14:00:35 +0000 (Tue, 05 May 2009)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1782-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1782-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1782-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1782");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mplayer' package(s) announced via the DSA-1782-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in mplayer, a movie player for Unix-like systems. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0385

It was discovered that watching a malformed 4X movie file could lead to the execution of arbitrary code.

CVE-2008-4866

It was discovered that multiple buffer overflows could lead to the execution of arbitrary code.

CVE-2008-5616

It was discovered that watching a malformed TwinVQ file could lead to the execution of arbitrary code.

For the oldstable distribution (etch), these problems have been fixed in version 1.0~rc1-12etch7.

For the stable distribution (lenny), mplayer links against ffmpeg-debian.

For the testing distribution (squeeze) and the unstable distribution (sid), mplayer links against ffmpeg-debian.

We recommend that you upgrade your mplayer packages.");

  script_tag(name:"affected", value:"'mplayer' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mplayer", ver:"1.0~rc1-12etch7", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mplayer-doc", ver:"1.0~rc1-12etch7", rls:"DEB4"))) {
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
