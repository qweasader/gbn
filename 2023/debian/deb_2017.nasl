# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2017");
  script_cve_id("CVE-2009-1299");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2017-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2017-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2017");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pulseaudio' package(s) announced via the DSA-2017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that the PulseAudio sound server creates a temporary directory with a predictable name. This allows a local attacker to create a Denial of Service condition or possibly disclose sensitive information to unprivileged users.

For the stable distribution (lenny), this problem has been fixed in version 0.9.10-3+lenny2.

For the testing (squeeze) and unstable (sid) distribution this problem will be fixed soon.

We recommend that you upgrade your pulseaudio package.");

  script_tag(name:"affected", value:"'pulseaudio' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-browse0", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-browse0", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-browse0-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-browse0-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-dev", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-dev", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-mainloop-glib0", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-mainloop-glib0", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-mainloop-glib0-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse-mainloop-glib0-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse0", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse0", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse0-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulse0-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulsecore5", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulsecore5", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulsecore5-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpulsecore5-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-esound-compat", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-esound-compat", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-esound-compat-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-esound-compat-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-gconf", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-gconf", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-gconf-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-gconf-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-hal", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-hal", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-hal-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-hal-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-jack", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-jack", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-jack-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-jack-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-lirc", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-lirc", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-lirc-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-lirc-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-x11", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-x11", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-x11-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-x11-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-utils", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-utils", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-utils-dbg", ver:"0.9.10-3+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pulseaudio-utils-dbg", ver:"0.9.10-3+lenny2+b1", rls:"DEB5"))) {
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
