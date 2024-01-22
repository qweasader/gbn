# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60269");
  script_cve_id("CVE-2008-0008");
  script_tag(name:"creation_date", value:"2008-01-31 18:16:52 +0000 (Thu, 31 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1476-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1476-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1476");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pulseaudio' package(s) announced via the DSA-1476-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcus Meissner discovered that the PulseAudio sound server performed insufficient checks when dropping privileges, which could lead to local privilege escalation.

The old stable distribution (sarge) doesn't contain pulseaudio.

For the stable distribution (etch), this problem has been fixed in version 0.9.5-5etch1.

We recommend that you upgrade your pulseaudio packages.");

  script_tag(name:"affected", value:"'pulseaudio' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-browse0", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-dev", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-mainloop-glib0", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse0", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-esound-compat", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-gconf", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-hal", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-jack", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-lirc", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-x11", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf", ver:"0.9.5-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-utils", ver:"0.9.5-5etch1", rls:"DEB4"))) {
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
