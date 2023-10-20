# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72535");
  script_cve_id("CVE-2012-4510");
  script_tag(name:"creation_date", value:"2012-10-29 14:19:57 +0000 (Mon, 29 Oct 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2562)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2562");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2562");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2562");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups-pk-helper' package(s) announced via the DSA-2562 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cups-pk-helper, a PolicyKit helper to configure CUPS with fine-grained privileges, wraps CUPS function calls in an insecure way. This could lead to uploading sensitive data to a CUPS resource, or overwriting specific files with the content of a CUPS resource. The user would have to explicitly approve the action.

For the stable distribution (squeeze), this problem has been fixed in version 0.1.0-3.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 0.2.3-1.

We recommend that you upgrade your cups-pk-helper packages.");

  script_tag(name:"affected", value:"'cups-pk-helper' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"cups-pk-helper", ver:"0.1.0-3", rls:"DEB6"))) {
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
