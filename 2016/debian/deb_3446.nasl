# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703446");
  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_tag(name:"creation_date", value:"2016-01-13 23:00:00 +0000 (Wed, 13 Jan 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-19 19:08:44 +0000 (Tue, 19 Jan 2016)");

  script_name("Debian: Security Advisory (DSA-3446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3446-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3446-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3446");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-3446-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qualys Security team discovered two vulnerabilities in the roaming code of the OpenSSH client (an implementation of the SSH protocol suite).

SSH roaming enables a client, in case an SSH connection breaks unexpectedly, to resume it at a later time, provided the server also supports it.

The OpenSSH server doesn't support roaming, but the OpenSSH client supports it (even though it's not documented) and it's enabled by default.

CVE-2016-0777

An information leak (memory disclosure) can be exploited by a rogue SSH server to trick a client into leaking sensitive data from the client memory, including for example private keys.

CVE-2016-0778

A buffer overflow (leading to file descriptor leak), can also be exploited by a rogue SSH server, but due to another bug in the code is possibly not exploitable, and only under certain conditions (not the default configuration), when using ProxyCommand, ForwardAgent or ForwardX11.

This security update completely disables the roaming code in the OpenSSH client.

It is also possible to disable roaming by adding the (undocumented) option UseRoaming no to the global /etc/ssh/ssh_config file, or to the user configuration in ~/.ssh/config, or by passing -oUseRoaming=no on the command line.

Users with passphrase-less private keys, especially in non interactive setups (automated jobs using ssh, scp, rsync+ssh etc.) are advised to update their keys if they have connected to an SSH server they don't trust.

More details about identifying an attack and mitigations will be available in the Qualys Security Advisory.

For the oldstable distribution (wheezy), these problems have been fixed in version 1:6.0p1-4+deb7u3.

For the stable distribution (jessie), these problems have been fixed in version 1:6.7p1-5+deb8u1.

For the testing distribution (stretch) and unstable distribution (sid), these problems will be fixed in a later version.

We recommend that you upgrade your openssh packages.");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:6.0p1-4+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client-udeb", ver:"1:6.0p1-4+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:6.0p1-4+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server-udeb", ver:"1:6.0p1-4+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh", ver:"1:6.0p1-4+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:6.0p1-4+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:6.0p1-4+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:6.7p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client-udeb", ver:"1:6.7p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:6.7p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server-udeb", ver:"1:6.7p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:6.7p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh", ver:"1:6.7p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:6.7p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:6.7p1-5+deb8u1", rls:"DEB8"))) {
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
