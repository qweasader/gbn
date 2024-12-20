# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703165");
  script_cve_id("CVE-2015-1877");
  script_tag(name:"creation_date", value:"2015-02-20 23:00:00 +0000 (Fri, 20 Feb 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 14:01:20 +0000 (Mon, 14 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-3165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3165-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3165-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3165");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xdg-utils' package(s) announced via the DSA-3165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jiri Horner discovered a way to cause xdg-open, a tool that automatically opens URLs in a user's preferred application, to execute arbitrary commands remotely.

This problem only affects /bin/sh implementations that don't sanitize local variables. Dash, which is the default /bin/sh in Debian is affected. Bash as /bin/sh is known to be unaffected.

For the stable distribution (wheezy), this problem has been fixed in version 1.1.0~rc1+git20111210-6+deb7u3.

For the upcoming stable (jessie) and unstable (sid) distributions, this problem will be fixed soon.

We recommend that you upgrade your xdg-utils packages.");

  script_tag(name:"affected", value:"'xdg-utils' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"xdg-utils", ver:"1.1.0~rc1+git20111210-6+deb7u3", rls:"DEB7"))) {
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
