# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53400");
  script_cve_id("CVE-2002-0658");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-137)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-137");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/dsa-137");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-137");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mm' package(s) announced via the DSA-137 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcus Meissner and Sebastian Krahmer discovered and fixed a temporary file vulnerability in the mm shared memory library. This problem can be exploited to gain root access to a machine running Apache which is linked against this library, if shell access to the user 'www-data' is already available (which could easily be triggered through PHP).

This problem has been fixed in the upstream version 1.2.0 of mm, which will be uploaded to the unstable Debian distribution while this advisory is released. Fixed packages for potato (Debian 2.2) and woody (Debian 3.0) are linked below.

We recommend that you upgrade your libmm packages immediately and restart your Apache server.");

  script_tag(name:"affected", value:"'mm' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"libmm11", ver:"1.1.3-6.1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmm11-dev", ver:"1.1.3-6.1", rls:"DEB3.0"))) {
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
